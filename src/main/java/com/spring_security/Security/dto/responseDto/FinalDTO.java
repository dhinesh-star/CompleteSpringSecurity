package com.spring_security.Security.dto.responseDto;

import lombok.*;

@Data
@Builder // Must have All Args Constructor
@AllArgsConstructor
@NoArgsConstructor
public class FinalDTO {
    int status;
    Object data;
}
