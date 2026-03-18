.class public final Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final getClassNameIndex(Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;Ljava/lang/String;)I
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "name"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/km/ClassNameKt;->isLocalClassName(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    invoke-virtual {p1, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const-string v1, "substring(...)"

    .line 23
    .line 24
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p0, p1, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;->getQualifiedClassNameIndex(Ljava/lang/String;Z)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    :cond_0
    const/4 v0, 0x0

    .line 33
    invoke-interface {p0, p1, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;->getQualifiedClassNameIndex(Ljava/lang/String;Z)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    return p0
.end method

.method public static final writeAnnotation(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "strings"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;->getClassName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-static {p1, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->getClassNameIndex(Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;->setId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;->getArguments()Ljava/util/Map;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_0

    .line 43
    .line 44
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/util/Map$Entry;

    .line 49
    .line 50
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    check-cast v2, Ljava/lang/String;

    .line 55
    .line 56
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 61
    .line 62
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Builder;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-interface {p1, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;->getStringIndex(Ljava/lang/String;)I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-virtual {v3, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Builder;->setNameId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Builder;

    .line 71
    .line 72
    .line 73
    invoke-static {v1, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->writeAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {v3, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Builder;->setValue(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Builder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0, v3}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;->addArgument(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Builder;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_0
    return-object v0
.end method

.method public static final writeAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "strings"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ByteValue;

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->BYTE:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 22
    .line 23
    .line 24
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ByteValue;

    .line 25
    .line 26
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ByteValue;->getValue()Ljava/lang/Byte;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    int-to-long p0, p0

    .line 35
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 36
    .line 37
    .line 38
    goto/16 :goto_2

    .line 39
    .line 40
    :cond_0
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$CharValue;

    .line 41
    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->CHAR:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 45
    .line 46
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 47
    .line 48
    .line 49
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$CharValue;

    .line 50
    .line 51
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$CharValue;->getValue()Ljava/lang/Character;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    int-to-long p0, p0

    .line 60
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 61
    .line 62
    .line 63
    goto/16 :goto_2

    .line 64
    .line 65
    :cond_1
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ShortValue;

    .line 66
    .line 67
    if-eqz v1, :cond_2

    .line 68
    .line 69
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->SHORT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 70
    .line 71
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 72
    .line 73
    .line 74
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ShortValue;

    .line 75
    .line 76
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ShortValue;->getValue()Ljava/lang/Short;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {p0}, Ljava/lang/Short;->shortValue()S

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    int-to-long p0, p0

    .line 85
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 86
    .line 87
    .line 88
    goto/16 :goto_2

    .line 89
    .line 90
    :cond_2
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$IntValue;

    .line 91
    .line 92
    if-eqz v1, :cond_3

    .line 93
    .line 94
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->INT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 95
    .line 96
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 97
    .line 98
    .line 99
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$IntValue;

    .line 100
    .line 101
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$IntValue;->getValue()Ljava/lang/Integer;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    int-to-long p0, p0

    .line 110
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 111
    .line 112
    .line 113
    goto/16 :goto_2

    .line 114
    .line 115
    :cond_3
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;

    .line 116
    .line 117
    if-eqz v1, :cond_4

    .line 118
    .line 119
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->LONG:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 120
    .line 121
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 122
    .line 123
    .line 124
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;

    .line 125
    .line 126
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->getValue()Ljava/lang/Long;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 131
    .line 132
    .line 133
    move-result-wide p0

    .line 134
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 135
    .line 136
    .line 137
    goto/16 :goto_2

    .line 138
    .line 139
    :cond_4
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$FloatValue;

    .line 140
    .line 141
    if-eqz v1, :cond_5

    .line 142
    .line 143
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->FLOAT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 144
    .line 145
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 146
    .line 147
    .line 148
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$FloatValue;

    .line 149
    .line 150
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$FloatValue;->getValue()Ljava/lang/Float;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setFloatValue(F)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 159
    .line 160
    .line 161
    goto/16 :goto_2

    .line 162
    .line 163
    :cond_5
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$DoubleValue;

    .line 164
    .line 165
    if-eqz v1, :cond_6

    .line 166
    .line 167
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->DOUBLE:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 168
    .line 169
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 170
    .line 171
    .line 172
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$DoubleValue;

    .line 173
    .line 174
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$DoubleValue;->getValue()Ljava/lang/Double;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    .line 179
    .line 180
    .line 181
    move-result-wide p0

    .line 182
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setDoubleValue(D)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 183
    .line 184
    .line 185
    goto/16 :goto_2

    .line 186
    .line 187
    :cond_6
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$BooleanValue;

    .line 188
    .line 189
    if-eqz v1, :cond_8

    .line 190
    .line 191
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->BOOLEAN:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 192
    .line 193
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 194
    .line 195
    .line 196
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$BooleanValue;

    .line 197
    .line 198
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$BooleanValue;->getValue()Ljava/lang/Boolean;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 203
    .line 204
    .line 205
    move-result p0

    .line 206
    if-eqz p0, :cond_7

    .line 207
    .line 208
    const-wide/16 p0, 0x1

    .line 209
    .line 210
    goto :goto_0

    .line 211
    :cond_7
    const-wide/16 p0, 0x0

    .line 212
    .line 213
    :goto_0
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 214
    .line 215
    .line 216
    goto/16 :goto_2

    .line 217
    .line 218
    :cond_8
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UByteValue;

    .line 219
    .line 220
    if-eqz v1, :cond_9

    .line 221
    .line 222
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->BYTE:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 223
    .line 224
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 225
    .line 226
    .line 227
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UByteValue;

    .line 228
    .line 229
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UByteValue;->getValue-w2LRezQ()B

    .line 230
    .line 231
    .line 232
    move-result p0

    .line 233
    int-to-long p0, p0

    .line 234
    const-wide/16 v1, 0xff

    .line 235
    .line 236
    and-long/2addr p0, v1

    .line 237
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 238
    .line 239
    .line 240
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->IS_UNSIGNED:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 241
    .line 242
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 243
    .line 244
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 245
    .line 246
    .line 247
    move-result p0

    .line 248
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 249
    .line 250
    .line 251
    goto/16 :goto_2

    .line 252
    .line 253
    :cond_9
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;

    .line 254
    .line 255
    if-eqz v1, :cond_a

    .line 256
    .line 257
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->SHORT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 258
    .line 259
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 260
    .line 261
    .line 262
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;

    .line 263
    .line 264
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->getValue-Mh2AYeg()S

    .line 265
    .line 266
    .line 267
    move-result p0

    .line 268
    int-to-long p0, p0

    .line 269
    const-wide/32 v1, 0xffff

    .line 270
    .line 271
    .line 272
    and-long/2addr p0, v1

    .line 273
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 274
    .line 275
    .line 276
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->IS_UNSIGNED:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 277
    .line 278
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 279
    .line 280
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 281
    .line 282
    .line 283
    move-result p0

    .line 284
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 285
    .line 286
    .line 287
    goto/16 :goto_2

    .line 288
    .line 289
    :cond_a
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UIntValue;

    .line 290
    .line 291
    if-eqz v1, :cond_b

    .line 292
    .line 293
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->INT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 294
    .line 295
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 296
    .line 297
    .line 298
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UIntValue;

    .line 299
    .line 300
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UIntValue;->getValue-pVg5ArA()I

    .line 301
    .line 302
    .line 303
    move-result p0

    .line 304
    int-to-long p0, p0

    .line 305
    const-wide v1, 0xffffffffL

    .line 306
    .line 307
    .line 308
    .line 309
    .line 310
    and-long/2addr p0, v1

    .line 311
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 312
    .line 313
    .line 314
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->IS_UNSIGNED:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 315
    .line 316
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 317
    .line 318
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 319
    .line 320
    .line 321
    move-result p0

    .line 322
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 323
    .line 324
    .line 325
    goto/16 :goto_2

    .line 326
    .line 327
    :cond_b
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;

    .line 328
    .line 329
    if-eqz v1, :cond_c

    .line 330
    .line 331
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->LONG:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 332
    .line 333
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 334
    .line 335
    .line 336
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;

    .line 337
    .line 338
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->getValue-s-VKNKU()J

    .line 339
    .line 340
    .line 341
    move-result-wide p0

    .line 342
    invoke-virtual {v0, p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setIntValue(J)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 343
    .line 344
    .line 345
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->IS_UNSIGNED:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 346
    .line 347
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 348
    .line 349
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 350
    .line 351
    .line 352
    move-result p0

    .line 353
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 354
    .line 355
    .line 356
    goto/16 :goto_2

    .line 357
    .line 358
    :cond_c
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$StringValue;

    .line 359
    .line 360
    if-eqz v1, :cond_d

    .line 361
    .line 362
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->STRING:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 363
    .line 364
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 365
    .line 366
    .line 367
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$StringValue;

    .line 368
    .line 369
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$StringValue;->getValue()Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object p0

    .line 373
    invoke-interface {p1, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;->getStringIndex(Ljava/lang/String;)I

    .line 374
    .line 375
    .line 376
    move-result p0

    .line 377
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setStringValue(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 378
    .line 379
    .line 380
    goto/16 :goto_2

    .line 381
    .line 382
    :cond_d
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$KClassValue;

    .line 383
    .line 384
    if-eqz v1, :cond_e

    .line 385
    .line 386
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->CLASS:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 387
    .line 388
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 389
    .line 390
    .line 391
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$KClassValue;

    .line 392
    .line 393
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$KClassValue;->getClassName()Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    move-result-object p0

    .line 397
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->getClassNameIndex(Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;Ljava/lang/String;)I

    .line 398
    .line 399
    .line 400
    move-result p0

    .line 401
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setClassId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 402
    .line 403
    .line 404
    goto/16 :goto_2

    .line 405
    .line 406
    :cond_e
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayKClassValue;

    .line 407
    .line 408
    if-eqz v1, :cond_f

    .line 409
    .line 410
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->CLASS:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 411
    .line 412
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 413
    .line 414
    .line 415
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayKClassValue;

    .line 416
    .line 417
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayKClassValue;->getClassName()Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v1

    .line 421
    invoke-static {p1, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->getClassNameIndex(Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;Ljava/lang/String;)I

    .line 422
    .line 423
    .line 424
    move-result p1

    .line 425
    invoke-virtual {v0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setClassId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 426
    .line 427
    .line 428
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayKClassValue;->getArrayDimensionCount()I

    .line 429
    .line 430
    .line 431
    move-result p0

    .line 432
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setArrayDimensionCount(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 433
    .line 434
    .line 435
    goto :goto_2

    .line 436
    :cond_f
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$EnumValue;

    .line 437
    .line 438
    if-eqz v1, :cond_10

    .line 439
    .line 440
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->ENUM:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 441
    .line 442
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 443
    .line 444
    .line 445
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$EnumValue;

    .line 446
    .line 447
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$EnumValue;->getEnumClassName()Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object v1

    .line 451
    invoke-static {p1, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->getClassNameIndex(Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;Ljava/lang/String;)I

    .line 452
    .line 453
    .line 454
    move-result v1

    .line 455
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setClassId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 456
    .line 457
    .line 458
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$EnumValue;->getEnumEntryName()Ljava/lang/String;

    .line 459
    .line 460
    .line 461
    move-result-object p0

    .line 462
    invoke-interface {p1, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;->getStringIndex(Ljava/lang/String;)I

    .line 463
    .line 464
    .line 465
    move-result p0

    .line 466
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setEnumValueId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 467
    .line 468
    .line 469
    goto :goto_2

    .line 470
    :cond_10
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$AnnotationValue;

    .line 471
    .line 472
    if-eqz v1, :cond_11

    .line 473
    .line 474
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->ANNOTATION:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 475
    .line 476
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 477
    .line 478
    .line 479
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$AnnotationValue;

    .line 480
    .line 481
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$AnnotationValue;->getAnnotation()Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;

    .line 482
    .line 483
    .line 484
    move-result-object p0

    .line 485
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->writeAnnotation(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;

    .line 486
    .line 487
    .line 488
    move-result-object p0

    .line 489
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;

    .line 490
    .line 491
    .line 492
    move-result-object p0

    .line 493
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setAnnotation(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 494
    .line 495
    .line 496
    goto :goto_2

    .line 497
    :cond_11
    instance-of v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayValue;

    .line 498
    .line 499
    if-eqz v1, :cond_13

    .line 500
    .line 501
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;->ARRAY:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 502
    .line 503
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 504
    .line 505
    .line 506
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayValue;

    .line 507
    .line 508
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayValue;->getElements()Ljava/util/List;

    .line 509
    .line 510
    .line 511
    move-result-object p0

    .line 512
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 513
    .line 514
    .line 515
    move-result-object p0

    .line 516
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 517
    .line 518
    .line 519
    move-result v1

    .line 520
    if-eqz v1, :cond_12

    .line 521
    .line 522
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 523
    .line 524
    .line 525
    move-result-object v1

    .line 526
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 527
    .line 528
    invoke-static {v1, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->writeAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 529
    .line 530
    .line 531
    move-result-object v1

    .line 532
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->addArrayElement(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 533
    .line 534
    .line 535
    goto :goto_1

    .line 536
    :cond_12
    :goto_2
    const-string p0, "apply(...)"

    .line 537
    .line 538
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    return-object v0

    .line 542
    :cond_13
    new-instance p0, La8/r0;

    .line 543
    .line 544
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 545
    .line 546
    .line 547
    throw p0
.end method
