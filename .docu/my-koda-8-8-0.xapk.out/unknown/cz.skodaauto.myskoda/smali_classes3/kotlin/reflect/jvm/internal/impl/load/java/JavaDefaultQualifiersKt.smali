.class public final Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final APPLICABILITY_OF_JAVAX_DEFAULTS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;",
            ">;"
        }
    .end annotation
.end field

.field private static final APPLICABILITY_OF_JSPECIFY_DEFAULTS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;",
            ">;"
        }
    .end annotation
.end field

.field private static final BUILT_IN_TYPE_QUALIFIER_DEFAULT_ANNOTATIONS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            "Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;",
            ">;"
        }
    .end annotation
.end field

.field private static final JAVAX_DEFAULT_ANNOTATIONS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            "Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;",
            ">;"
        }
    .end annotation
.end field

.field private static final JSPECIFY_DEFAULT_ANNOTATIONS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            "Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 18

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;->FIELD:Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;->METHOD_RETURN_TYPE:Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;

    .line 4
    .line 5
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;->VALUE_PARAMETER:Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;

    .line 6
    .line 7
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;->TYPE_PARAMETER_BOUNDS:Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;

    .line 8
    .line 9
    sget-object v4, Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;->TYPE_USE:Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;

    .line 10
    .line 11
    filled-new-array {v0, v1, v2, v3, v4}, [Lkotlin/reflect/jvm/internal/impl/load/java/AnnotationQualifierApplicabilityType;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->APPLICABILITY_OF_JSPECIFY_DEFAULTS:Ljava/util/List;

    .line 20
    .line 21
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->APPLICABILITY_OF_JAVAX_DEFAULTS:Ljava/util/List;

    .line 26
    .line 27
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->getJSPECIFY_OLD_NULL_MARKED_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    new-instance v3, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;

    .line 32
    .line 33
    new-instance v4, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;

    .line 34
    .line 35
    sget-object v5, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;->NOT_NULL:Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x0

    .line 40
    invoke-direct {v4, v5, v6, v7, v8}, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;ZILkotlin/jvm/internal/g;)V

    .line 41
    .line 42
    .line 43
    move-object v11, v0

    .line 44
    check-cast v11, Ljava/util/Collection;

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    invoke-direct {v3, v4, v11, v6, v0}, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;Ljava/util/Collection;ZZ)V

    .line 48
    .line 49
    .line 50
    new-instance v4, Llx0/l;

    .line 51
    .line 52
    invoke-direct {v4, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->getJSPECIFY_NULL_MARKED_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    new-instance v3, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;

    .line 60
    .line 61
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;

    .line 62
    .line 63
    invoke-direct {v9, v5, v6, v7, v8}, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;ZILkotlin/jvm/internal/g;)V

    .line 64
    .line 65
    .line 66
    invoke-direct {v3, v9, v11, v6, v0}, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;Ljava/util/Collection;ZZ)V

    .line 67
    .line 68
    .line 69
    new-instance v0, Llx0/l;

    .line 70
    .line 71
    invoke-direct {v0, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->getJSPECIFY_NULL_UNMARKED_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;

    .line 79
    .line 80
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;

    .line 81
    .line 82
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;->FORCE_FLEXIBILITY:Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;

    .line 83
    .line 84
    invoke-direct {v10, v3, v6, v7, v8}, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;ZILkotlin/jvm/internal/g;)V

    .line 85
    .line 86
    .line 87
    const/4 v14, 0x4

    .line 88
    const/4 v15, 0x0

    .line 89
    const/4 v12, 0x0

    .line 90
    const/4 v13, 0x1

    .line 91
    invoke-direct/range {v9 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;Ljava/util/Collection;ZZILkotlin/jvm/internal/g;)V

    .line 92
    .line 93
    .line 94
    new-instance v3, Llx0/l;

    .line 95
    .line 96
    invoke-direct {v3, v2, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    filled-new-array {v4, v0, v3}, [Llx0/l;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-static {v0}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->JSPECIFY_DEFAULT_ANNOTATIONS:Ljava/util/Map;

    .line 108
    .line 109
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->getJAVAX_PARAMETERS_ARE_NONNULL_BY_DEFAULT_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;

    .line 114
    .line 115
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;

    .line 116
    .line 117
    invoke-direct {v10, v5, v6, v7, v8}, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;ZILkotlin/jvm/internal/g;)V

    .line 118
    .line 119
    .line 120
    move-object v11, v1

    .line 121
    check-cast v11, Ljava/util/Collection;

    .line 122
    .line 123
    const/16 v14, 0xc

    .line 124
    .line 125
    const/4 v13, 0x0

    .line 126
    invoke-direct/range {v9 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;Ljava/util/Collection;ZZILkotlin/jvm/internal/g;)V

    .line 127
    .line 128
    .line 129
    new-instance v1, Llx0/l;

    .line 130
    .line 131
    invoke-direct {v1, v2, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->getJAVAX_PARAMETERS_ARE_NULLABLE_BY_DEFAULT_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    move-object v13, v11

    .line 139
    new-instance v11, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;

    .line 140
    .line 141
    new-instance v12, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;

    .line 142
    .line 143
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;->NULLABLE:Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;

    .line 144
    .line 145
    invoke-direct {v12, v3, v6, v7, v8}, Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifier;ZILkotlin/jvm/internal/g;)V

    .line 146
    .line 147
    .line 148
    const/16 v16, 0xc

    .line 149
    .line 150
    const/16 v17, 0x0

    .line 151
    .line 152
    const/4 v14, 0x0

    .line 153
    const/4 v15, 0x0

    .line 154
    invoke-direct/range {v11 .. v17}, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/typeEnhancement/NullabilityQualifierWithMigrationStatus;Ljava/util/Collection;ZZILkotlin/jvm/internal/g;)V

    .line 155
    .line 156
    .line 157
    new-instance v3, Llx0/l;

    .line 158
    .line 159
    invoke-direct {v3, v2, v11}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    filled-new-array {v1, v3}, [Llx0/l;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-static {v1}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->JAVAX_DEFAULT_ANNOTATIONS:Ljava/util/Map;

    .line 171
    .line 172
    invoke-static {v0, v1}, Lmx0/x;->p(Ljava/util/Map;Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->BUILT_IN_TYPE_QUALIFIER_DEFAULT_ANNOTATIONS:Ljava/util/Map;

    .line 177
    .line 178
    return-void
.end method

.method public static final getBUILT_IN_TYPE_QUALIFIER_DEFAULT_ANNOTATIONS()Ljava/util/Map;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            "Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->BUILT_IN_TYPE_QUALIFIER_DEFAULT_ANNOTATIONS:Ljava/util/Map;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJSPECIFY_DEFAULT_ANNOTATIONS()Ljava/util/Map;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            "Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiers;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JavaDefaultQualifiersKt;->JSPECIFY_DEFAULT_ANNOTATIONS:Ljava/util/Map;

    .line 2
    .line 3
    return-object v0
.end method
