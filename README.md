# .conf2024 SEC1186C New High Score: How to Play RBA and Win!



# Searches from Slides

# Risk Score Check:
| from datamodel:"Risk"
| table source risk_factor_add risk_factor_mult risk_score


# Velocity Tracking:
| from datamodel:"Risk"."All_Risk" 
| search `risk_notable_sources` 
| stats count by search_name 
| eval avg=round(count/30) 
| eval velocity=case(avg<=1,1.25,avg>1 AND avg<=50,1,avg>50 AND avg<=100,0.75,avg>100 AND avg<=500,0.5,avg>500,0.25)
| outputlookup  risk_velocity.csv


# Risk Score Limit:
| eval risk_ScoreSum=if(risk_ScoreSum>500, risk_ScoreSum/5, risk_ScoreSum) 


# Velocity Risk Score:
| eval new_risk_score=(usecase_weight+mitre_weight)*velocity


# Alert Disposition Tracking:
`get_notable_index` 
| eval `get_event_id_meval`, rule_id=event_id, temp_time=time()+86400
| `suppression_extract` | search NOT suppression=*
| lookup update=true correlationsearches_lookup _key as source OUTPUTNEW default_disposition
| lookup update=true event_time_field=temp_time incident_review_lookup rule_id OUTPUT disposition as new_disposition
| eval disposition=if(isnotnull(new_disposition),new_disposition,default_disposition)
| `get_notable_disposition`
| stats count as event_count by disposition_label, search_name, severity
| eval closed_weighted_score = case(event_count <= 10, 1.5, event_count <= 20, 1, event_count > 20, 0.5)
| outputlookup alert_disposition_tracking.csv 


# Risk Score Calcuation:
| eval new_risk_score=((usecase_weight+mitre_weight)*velocity)*closed_weighted_score
