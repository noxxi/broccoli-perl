%module broccoli_intern
%{
#include <broccoli.h>
#include <stdint.h>

// Broccoli internal struct. Easier to copy that here than to include a bunch
// of Broccoli's internal headers.
struct bro_record {
    void *val_list;
    int val_len;
};
typedef BroRecord bro_record;

SV * _av(AV* array,int idx)
{
    SV **v = av_fetch(array,idx,0); 
    if (v) return *v;
    croak("no array value at index %d",idx);
    return 0;
}

int type2i(const char* type) 
{

    if (!strcmp(type,"bool")) return BRO_TYPE_BOOL;
    if (!strcmp(type,"int")) return BRO_TYPE_INT;
    if (!strcmp(type,"count")) return BRO_TYPE_COUNT;
    if (!strcmp(type,"counter")) return BRO_TYPE_COUNTER;
    if (!strcmp(type,"ipaddr")) return BRO_TYPE_IPADDR;
    if (!strcmp(type,"double")) return BRO_TYPE_DOUBLE;
    if (!strcmp(type,"time")) return BRO_TYPE_TIME;
    if (!strcmp(type,"interval")) return BRO_TYPE_INTERVAL;
    if (!strcmp(type,"string")) return BRO_TYPE_STRING;
    if (!strcmp(type,"enum")) return BRO_TYPE_ENUM;
    if (!strcmp(type,"port")) return BRO_TYPE_PORT;
    if (!strcmp(type,"subnet")) return BRO_TYPE_SUBNET;
    if (!strcmp(type,"record")) return BRO_TYPE_RECORD;
    if (!strcmp(type,"set")) return BRO_TYPE_SET;
    if (!strcmp(type,"unknown")) return BRO_TYPE_UNKNOWN;
    if (!strcmp(type,"table")) return BRO_TYPE_TABLE;
    croak("unknown type '%s'",type);
    return 0;
}


const char *i2type(int i)
{
    switch(i) {
	case BRO_TYPE_BOOL: return "bool";
	case BRO_TYPE_INT: return "int";
	case BRO_TYPE_COUNT: return "count";
	case BRO_TYPE_COUNTER: return "counter";
	case BRO_TYPE_IPADDR: return "ipaddr";
	case BRO_TYPE_DOUBLE: return "double";
	case BRO_TYPE_TIME: return "time";
	case BRO_TYPE_INTERVAL: return "interval";
	case BRO_TYPE_STRING: return "string";
	case BRO_TYPE_ENUM: return "enum";
	case BRO_TYPE_PORT: return "port";
	case BRO_TYPE_SUBNET: return "subnet";
	case BRO_TYPE_RECORD: return "record";
	case BRO_TYPE_SET: return "set";
	case BRO_TYPE_UNKNOWN: return "unknown";
	case BRO_TYPE_TABLE: return "table";
    }
    croak("unknown type '%d'",i);
    return 0;
}


// Release the memory associated with the Broccoli value.
void freeBroccoliVal(int type, void* data)
{
    if ( ! data )
	return;

    switch ( type ) {
      case BRO_TYPE_STRING:
	free(((BroString *)data)->str_val);
	free(data);
	break;

      case BRO_TYPE_RECORD:
	bro_record_free((BroRecord *)data);
	break;

      case BRO_TYPE_SET:
	bro_set_free((BroSet *)data);
	break;

      default:
	free(data);
    }

}

// Converts a Broccoli value into a Perl SV
// basic types will result in simple scalars, others in Broccoli::$type objects
SV* bc2sv(int type, void* data) 
{

    SV* val = 0;
    switch (type) {
	case BRO_TYPE_BOOL:
	    val = newSViv(*((int64_t *)data) ? 1:0 );
	    break;

	case BRO_TYPE_INT:
	    // XXX will break if too big and only 32bit integer
	    val = newSViv(*((int64_t *)data));
	    break;

	case BRO_TYPE_COUNT:
	case BRO_TYPE_COUNTER:
	    // XXX will break if too big and only 32bit integer
	    val = newSVuv(*((uint64_t *)data));
	    break;

	case BRO_TYPE_IPADDR: {
	    val = newSVpvn((char*)data,4);
	    SV *rv = newRV_noinc(val);
	    sv_bless(rv,gv_stashpv("Broccoli::ipaddr", TRUE));
	    val = rv;
	    break;
	}

	case BRO_TYPE_DOUBLE:
	case BRO_TYPE_TIME:
	case BRO_TYPE_INTERVAL:
	    val = newSVnv(*((double *)data));
	    break;

	case BRO_TYPE_STRING: {
	    BroString *str = (BroString*)data;
	    val = newSVpvn((const char*)str->str_val, str->str_len);
	    break;
	}

	case BRO_TYPE_ENUM:
	    val = (SV*)newAV();
	    av_push((AV*)val, newSVuv(*((int *)data)));
	    av_push((AV*)val, newSVpv("broccoli-doesnt-give-us-the-enum-type! :-(",0));
	    newSVrv((SV*)val,"Broccoli::enum");
	    break;

	case BRO_TYPE_PORT: {
	    BroPort *port = (BroPort*)data;
	    val = (SV*)newAV();
	    av_push((AV*)val,newSViv(port->port_num));
	    av_push((AV*)val,newSViv(port->port_proto));
	    SV *rv = newRV_noinc(val);
	    sv_bless(rv,gv_stashpv("Broccoli::port", TRUE));
	    val = rv;
	    break;
	}

	case BRO_TYPE_SUBNET: {
	    BroSubnet *subnet = (BroSubnet*)data;
	    val = (SV*)newAV();
	    av_push((AV*)val,newSVpvn((char*)&subnet->sn_net,4));
	    av_push((AV*)val,newSViv(subnet->sn_width));
	    SV *rv = newRV_noinc(val);
	    sv_bless(rv,gv_stashpv("Broccoli::subnet", TRUE));
	    val = rv;
	    break;
	}

	case BRO_TYPE_RECORD: {
	    BroRecord *rec = (BroRecord*)data;
	    val = (SV*)newHV();
	    HV *field2type = newHV();
	    hv_store((HV*)val,"\0f2t",4,newRV((SV*)field2type),0);

	    int i;
	    for ( i = 0; i < rec->val_len; i++ ) {
		int type = BRO_TYPE_UNKNOWN;
		const char *name = bro_record_get_nth_name(rec,i);
		void *data = bro_record_get_nth_val(rec, i, &type);
		AV *tuple = newAV();
		hv_store((HV*)val,name,strlen(name),bc2sv(type, data),0);
		hv_store(field2type,name,strlen(name),newSViv(type),0);
	    }
	    SV *rv = newRV_noinc(val);
	    sv_bless(rv,gv_stashpv("Broccoli::record", TRUE));
	    val = rv;
	    break;
	}

	case BRO_TYPE_SET: 
	case BRO_TYPE_TABLE: 
	case BRO_TYPE_UNKNOWN: 
	    // no idea for now :(
	    val = &PL_sv_undef;
	    break;

	default:
	    croak("unknown type %d",type);
	    return 0;
    }
    return val;
}

// Converts a Perl SV into Broccoli value.
int sv2bc(SV *val, int *type, const char **type_name, void** data)
{
    *type_name = 0;
    *data = 0;

    if ( *type > 0 && *type < BRO_TYPE_MAX ) {
	// hopfully not just forgotten to initialize
	// take type as given

    } else if ( ! SvROK(val)) {
	// simple scalar: guess
	if ( looks_like_number(val)) {
	    int i = SvIV(val);
	    double f = SvNV(val);
	    *type = ( (double)i == f ) ? BRO_TYPE_INT : BRO_TYPE_DOUBLE;
	} else {
	    *type = BRO_TYPE_STRING;
	}

    } else if ( ! sv_isobject(val)) {
	// should by [type,value] then
	AV* array = SvROK(val) ? (AV*)SvRV(val) : 0;
	if ( SvTYPE(SvRV(val)) != SVt_PVAV || av_len((AV*)SvRV(val))!=1 ) {
	    croak("argument must be [type,value]");
	    return 0;
	}

	SV *ptype = _av(array,0);
	*type = looks_like_number(ptype) ? SvIV(ptype):-1;
	if ( *type < 0 || *type > BRO_TYPE_MAX ) {
	    croak("unknown type %d",*type);
	    return 0;
	}
	val  = _av(array,1);

    } else {
	// take from object name
	*type = 
	    sv_isa(val,"Broccoli::int")      ? BRO_TYPE_INT :
	    sv_isa(val,"Broccoli::double")   ? BRO_TYPE_DOUBLE :
	    sv_isa(val,"Broccoli::string")   ? BRO_TYPE_STRING :
	    sv_isa(val,"Broccoli::bool")     ? BRO_TYPE_BOOL :
	    sv_isa(val,"Broccoli::count")    ? BRO_TYPE_COUNT :
	    sv_isa(val,"Broccoli::time")     ? BRO_TYPE_TIME :
	    sv_isa(val,"Broccoli::interval") ? BRO_TYPE_INTERVAL :
	    sv_isa(val,"Broccoli::ipaddr")   ? BRO_TYPE_IPADDR :
	    sv_isa(val,"Broccoli::enum")     ? BRO_TYPE_ENUM :
	    sv_isa(val,"Broccoli::port")     ? BRO_TYPE_PORT :
	    sv_isa(val,"Broccoli::subnet")   ? BRO_TYPE_SUBNET :
	    sv_derived_from(val,"Broccoli::record") ? BRO_TYPE_RECORD:
	    -1;
	if (*type<0) {
	    croak("unknown broccoli type '%s'",HvNAME(SvSTASH(SvRV(val))));
	    return 0;
	}
    }

    switch (*type) {
	case BRO_TYPE_BOOL:
	case BRO_TYPE_INT: {
	    if (SvROK(val)) val = SvRV(val);
	    int64_t* tmp = (int64_t *)malloc(sizeof(int64_t));
	    *tmp = SvIV(val);
	    *data = tmp;
	    break;
	}

	case BRO_TYPE_COUNT:
	case BRO_TYPE_COUNTER: {
	    if (SvROK(val)) val = SvRV(val);
	    uint64_t* tmp = (uint64_t *)malloc(sizeof(uint64_t));
	    *tmp = SvUV(val);
	    *data = tmp;
	    break;
	}

	case BRO_TYPE_IPADDR: {
	    if (SvROK(val)) val = SvRV(val);
	    STRLEN len;
	    char *v = SvPV(val,len);
	    if (len!=4) {
		croak("ipaddr needs to be size 4 byte");
		return 0;
	    }
	    int *tmp = (void*)malloc(sizeof(int));
	    memcpy(tmp,v,sizeof(int));
	    *data = tmp;
	    break;
	}

	case BRO_TYPE_DOUBLE:
	case BRO_TYPE_TIME:
	case BRO_TYPE_INTERVAL: {
	    if (SvROK(val)) val = SvRV(val);
	    double* tmp = (double *)malloc(sizeof(double));
	    *tmp = SvNV(val);
	    *data = tmp;
	    break;
	}

	case BRO_TYPE_STRING: {
	    if (SvROK(val)) val = SvRV(val);
	    STRLEN len;
	    const char *tmp = SvPV(val,len);
	    if (!tmp) return 0;
	    BroString* str = (BroString *)malloc(sizeof(BroString));
	    str->str_val = (unsigned char*)malloc(len+1);
	    memcpy(str->str_val,tmp, str->str_len = len);
	    *data = str;
	    break;
	}

	case BRO_TYPE_ENUM: {
	    AV* array = SvROK(val) ? (AV*)SvRV(val) : 0;
	    if ( ! array || SvTYPE((SV*)array) != SVt_PVAV || av_len(array)!=1 ) {
		croak("enum must be [num,name]");
		return 0;
	    }

	    int type = SvIV(_av(array,0));
	    const char* enum_type = SvPV_nolen(_av(array,1));
	    if ( ! enum_type ) return 0;

	    int* tmp = (int *)malloc(sizeof(int));
	    *tmp = type;
	    *data = tmp;
	    *type_name = strdup(enum_type);
	    break;
	}

	case BRO_TYPE_PORT: {
	    AV* array = SvROK(val) ? (AV*)SvRV(val) : 0;
	    if ( ! array || SvTYPE((SV*)array) != SVt_PVAV || av_len(array)!=1 ) {
		croak("port must be [port,proto]");
		return 0;
	    }

	    BroPort* port = (BroPort *)malloc(sizeof(BroPort));
	    port->port_num = SvIV(_av(array,0));
	    port->port_proto = SvIV(_av(array,1));
	    *data = port;
	    break;
	}

	case BRO_TYPE_SUBNET: {
	    AV* array = SvROK(val) ? (AV*)SvRV(val) : 0;
	    if ( ! array || SvTYPE((SV*)array) != SVt_PVAV || av_len(array)!=1 ) {
		croak("subnet must be [net,mask]");
		return 0;
	    }

	    BroSubnet* subnet = (BroSubnet *)malloc(sizeof(BroSubnet));

	    STRLEN len;
	    char *v = SvPV(_av(array,0),len);
	    if (len!=4) {
		croak("subnet needs to be size 4 byte");
		return 0;
	    }
	    memcpy(&subnet->sn_net,v,sizeof(int));

	    subnet->sn_width = SvIV(_av(array,1));
	    *data = subnet;
	    break;
	}

	case BRO_TYPE_RECORD: {
	    HV* hash = SvROK(val) ? (HV*)SvRV(val) : 0;
	    if ( ! hash || SvTYPE((HV*)hash) != SVt_PVHV ) {
		croak("record must be hash-ref");
		return 0;
	    }

	    // field2type mapping is either in $val{"\0f2t"} or 
	    // in %class::field2type
	    HV *field2type = 0; 
	    SV **f2t = hv_fetch(hash,"\0f2t",4,0);
	    if (f2t) field2type = SvROK(*f2t) ? (HV*)SvRV(*f2t) : 0;

	    if ( ! field2type && sv_isobject(val)) {
		const char *class = HvNAME(SvSTASH(SvRV(val)));
		char *varname = malloc(strlen(class)+10);
		sprintf(varname,"%s::field2type",class);
		field2type = get_hv(varname,0);
		free(varname);
	    }

	    BroRecord *rec = bro_record_new();
	    int len;
	    char *fieldName;
	    SV *fval;

	    hv_iterinit(hash);
	    while ((fval = hv_iternextsv(hash,&fieldName,&len))) {
		if (len>1 && fieldName[0] == 0) // internal, like \0f2t
		    continue;

		int ftype = 0;
		const char *ftype_name;

		if ( field2type && ! sv_isobject(fval)) {
		    // no typed object, try to get info from field2type
		    SV **type = hv_fetch(field2type,fieldName,len,0);
		    if (!type && HvKEYS(field2type)>0 ) {
			croak("unknown key '%s' in record",fieldName);
			return 0;
		    }
		    if (looks_like_number(*type)) {
			ftype = SvIV(*type);
			ftype_name = i2type(ftype);
		    } else {
			ftype_name = SvPV_nolen(*type);
			ftype = type2i(ftype_name);
		    }

		    // upgrade val to object unless it's simple val
		    switch(ftype) {
			case BRO_TYPE_BOOL:
			case BRO_TYPE_INT:
			case BRO_TYPE_COUNT:
			case BRO_TYPE_COUNTER:
			case BRO_TYPE_DOUBLE:
			case BRO_TYPE_TIME:
			case BRO_TYPE_INTERVAL:
			case BRO_TYPE_STRING:
			    // simple type
			    break;
			default: {
			    // call constructor
			    char class[1024];
			    if (strlen(ftype_name)>1000) {
				croak("typename too long");
				return 0;
			    }
			    if (index(ftype_name,':')) {
				strcpy(class,ftype_name);
			    } else {
				sprintf(class,"Broccoli::%s",ftype_name);
			    }

			    dSP;
			    PUSHMARK(sp);
			    XPUSHs(sv_2mortal(newSVpv(class,0))); // classname
			    XPUSHs(fval);
			    PUTBACK;
			    int n = call_method("new",G_SCALAR);
			    SPAGAIN;
			    if (!n) {
				croak("failed to execute %s->new",class);
				return 0;
			    }
			    fval = POPs;
			    SvREFCNT_inc(fval);
			    PUTBACK;
			    FREETMPS;
			    LEAVE;

			    if(!SvOK(fval)) {
				croak("%s->new returned undef",class);
				return 0;
			    }
			}
		    }
		}

		void *fdata;
		if ( ! sv2bc(fval, &ftype, &ftype_name, &fdata) ) 
		    return 0;

		bro_record_add_val(rec, fieldName, ftype, 0, fdata);
		freeBroccoliVal(ftype, fdata);
	    }

	    *data = rec;
	    break;
	}

	default:
	    croak("unknown type %",*type);
	    return 0;
    }

    return 1;
}


// C-level event handler for events. We register all events with this callback,
// passing the target Perl function in via data.
void event_callback(BroConn *bc, void *data, BroEvMeta *meta)
{
    SV *func = (SV*)data;
    if ( SvTYPE(func) != SVt_PVCV ) {
	croak("callback must be function");
	return;
    }

    dSP;
    PUSHMARK(sp);
    int i;
    for ( i = 0; i < meta->ev_numargs; i++ ) {
	XPUSHs(sv_2mortal(bc2sv(meta->ev_args[i].arg_type, meta->ev_args[i].arg_data)));
    }
    PUTBACK;

    perl_call_sv(func,G_VOID|G_DISCARD);
}

%}

// For bro_event_registry_add_compact().
%typemap(in) (BroCompactEventFunc func, void *user_data)
{
    if ( ! SvROK($input) || SvTYPE(SvRV($input)) != SVt_PVCV ) {
	// Perl_sv_dump(aTHX_ $input);
	croak("callback must be a function reference");
	return;
    }

    $1 = event_callback;
    $2 = SvRV($input);
    SvREFCNT_inc($2);
}

// For bro_event_add_val() and bro_record_add_val().
%typemap(in) (int type, const char *type_name, const void *val)
{
    int type = 0;
    const char* type_name = 0;
    void *data = 0;

//bro_debug_messages = 1;
//bro_debug_calltrace = 1;

    if ( ! sv2bc($input, &type, &type_name, &data) )
	return;

    $1 = type;
    $2 = (char*)type_name; // swig declares $2 as char* only, why?
    $3 = data;
}

%typemap(freearg) (int type, const char *type_name, const void *val)
{
    // Broccoli makes copies of the passed data so we need to clean up.
    freeBroccoliVal($1, $3);

    if ( $2 )
	free($2);
}

// The exact types of these don't really matter as we're only
// passing pointers around.
typedef void BroCtx;
typedef void BroConn;
typedef void BroEvent;

int            bro_init(const BroCtx *ctx);
BroConn       *bro_conn_new_str(const char *hostname, int flags);
void           bro_conn_set_class(BroConn *bc, const char *classname);
int            bro_conn_connect(BroConn *bc);
int            bro_conn_process_input(BroConn *bc);
int            bro_event_queue_length(BroConn *bc);
BroEvent      *bro_event_new(const char *event_name);
void           bro_event_free(BroEvent *be);
int            bro_event_add_val(BroEvent *be, int type, const char *type_name,const void *val);
int            bro_event_send(BroConn *bc, BroEvent *be);
void           bro_event_registry_add_compact(BroConn *bc, const char *event_name, BroCompactEventFunc func, void *user_data);
double         bro_util_current_time(void);
int            bro_conn_get_fd(BroConn *bc);
SV*            bc2sv(int type, void* data);
