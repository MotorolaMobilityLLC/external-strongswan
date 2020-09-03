#ifndef __comm_alerts_h
#define __comm_alerts_h

int get_alerts_index(char *name);
void free_alerts_index(int index);
int get_alerts_notify(int index);
void *get_alerts_vendor_container(int index);
charon_error_code_t get_error_from_alerts(int index);
void set_alert(ike_sa_t *ike_sa, alert_t alert, va_list args);

#endif
