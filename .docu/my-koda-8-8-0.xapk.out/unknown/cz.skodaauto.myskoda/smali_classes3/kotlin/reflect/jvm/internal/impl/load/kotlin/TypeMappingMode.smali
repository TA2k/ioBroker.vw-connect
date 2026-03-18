.class public final Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$Companion;,
        Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$WhenMappings;
    }
.end annotation


# static fields
.field public static final CLASS_DECLARATION:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final Companion:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$Companion;

.field public static final DEFAULT:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final DEFAULT_UAST:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final GENERIC_ARGUMENT:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final GENERIC_ARGUMENT_FOR_SUPER_TYPES_AS_IS:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final GENERIC_ARGUMENT_UAST:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final INVOKE_DYNAMIC_BOOTSTRAP_ARGUMENT:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final RETURN_TYPE_BOXED:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final SUPER_TYPE:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final SUPER_TYPE_AS_IS:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final SUPER_TYPE_KOTLIN_COLLECTIONS_AS_IS:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field public static final VALUE_FOR_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;


# instance fields
.field private final genericArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field private final genericContravariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field private final genericInvariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

.field private final ignoreTypeArgumentsBounds:Z

.field private final isForAnnotationParameter:Z

.field private final kotlinCollectionsToJavaCollections:Z

.field private final mapTypeAliases:Z

.field private final needInlineClassWrapping:Z

.field private final needPrimitiveBoxing:Z

.field private final skipDeclarationSiteWildcards:Z

.field private final skipDeclarationSiteWildcardsIfPossible:Z


# direct methods
.method static constructor <clinit>()V
    .locals 23

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->Companion:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$Companion;

    .line 8
    .line 9
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 10
    .line 11
    const/16 v14, 0x7ff

    .line 12
    .line 13
    const/4 v15, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x0

    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v7, 0x0

    .line 19
    move-object v2, v8

    .line 20
    const/4 v8, 0x0

    .line 21
    const/4 v9, 0x0

    .line 22
    const/4 v10, 0x0

    .line 23
    const/4 v11, 0x0

    .line 24
    const/4 v12, 0x0

    .line 25
    const/4 v13, 0x0

    .line 26
    invoke-direct/range {v2 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 27
    .line 28
    .line 29
    move-object v8, v2

    .line 30
    sput-object v8, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->GENERIC_ARGUMENT:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 31
    .line 32
    new-instance v15, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 33
    .line 34
    const/16 v21, 0x3ff

    .line 35
    .line 36
    const/16 v22, 0x0

    .line 37
    .line 38
    const/4 v10, 0x0

    .line 39
    const/4 v11, 0x0

    .line 40
    const/4 v14, 0x0

    .line 41
    move-object v9, v15

    .line 42
    const/4 v15, 0x0

    .line 43
    const/16 v16, 0x0

    .line 44
    .line 45
    const/16 v17, 0x0

    .line 46
    .line 47
    const/16 v18, 0x0

    .line 48
    .line 49
    const/16 v19, 0x0

    .line 50
    .line 51
    const/16 v20, 0x1

    .line 52
    .line 53
    invoke-direct/range {v9 .. v22}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 54
    .line 55
    .line 56
    move-object v0, v9

    .line 57
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->GENERIC_ARGUMENT_FOR_SUPER_TYPES_AS_IS:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 58
    .line 59
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 60
    .line 61
    const/16 v21, 0x5ff

    .line 62
    .line 63
    const/16 v19, 0x1

    .line 64
    .line 65
    const/16 v20, 0x0

    .line 66
    .line 67
    invoke-direct/range {v9 .. v22}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 68
    .line 69
    .line 70
    move-object v1, v9

    .line 71
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->GENERIC_ARGUMENT_UAST:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 72
    .line 73
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 74
    .line 75
    const/16 v21, 0x7fd

    .line 76
    .line 77
    const/4 v11, 0x1

    .line 78
    const/16 v19, 0x0

    .line 79
    .line 80
    invoke-direct/range {v9 .. v22}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 81
    .line 82
    .line 83
    sput-object v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->RETURN_TYPE_BOXED:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 84
    .line 85
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 86
    .line 87
    const/16 v14, 0x7dc

    .line 88
    .line 89
    const/4 v9, 0x0

    .line 90
    const/4 v10, 0x0

    .line 91
    const/4 v11, 0x0

    .line 92
    invoke-direct/range {v2 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 93
    .line 94
    .line 95
    sput-object v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->DEFAULT:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 96
    .line 97
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 98
    .line 99
    const/16 v21, 0x5dc

    .line 100
    .line 101
    const/4 v10, 0x0

    .line 102
    const/4 v11, 0x0

    .line 103
    const/4 v14, 0x0

    .line 104
    const/16 v19, 0x1

    .line 105
    .line 106
    move-object v15, v1

    .line 107
    invoke-direct/range {v9 .. v22}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 108
    .line 109
    .line 110
    sput-object v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->DEFAULT_UAST:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 111
    .line 112
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 113
    .line 114
    const/16 v14, 0x7dc

    .line 115
    .line 116
    const/4 v15, 0x0

    .line 117
    const/4 v4, 0x1

    .line 118
    const/4 v9, 0x0

    .line 119
    const/4 v10, 0x0

    .line 120
    const/4 v11, 0x0

    .line 121
    invoke-direct/range {v2 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 122
    .line 123
    .line 124
    sput-object v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->CLASS_DECLARATION:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 125
    .line 126
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 127
    .line 128
    const/16 v14, 0x7d7

    .line 129
    .line 130
    const/4 v4, 0x0

    .line 131
    const/4 v6, 0x1

    .line 132
    invoke-direct/range {v2 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 133
    .line 134
    .line 135
    sput-object v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->SUPER_TYPE:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 136
    .line 137
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 138
    .line 139
    const/16 v21, 0x3d7

    .line 140
    .line 141
    const/4 v10, 0x0

    .line 142
    const/4 v11, 0x0

    .line 143
    const/4 v13, 0x1

    .line 144
    const/4 v14, 0x0

    .line 145
    const/16 v19, 0x0

    .line 146
    .line 147
    const/16 v20, 0x1

    .line 148
    .line 149
    move-object v15, v0

    .line 150
    invoke-direct/range {v9 .. v22}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 151
    .line 152
    .line 153
    move-object v0, v9

    .line 154
    move-object v9, v15

    .line 155
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->SUPER_TYPE_AS_IS:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 156
    .line 157
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 158
    .line 159
    const/16 v21, 0x397

    .line 160
    .line 161
    invoke-direct/range {v9 .. v22}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 162
    .line 163
    .line 164
    sput-object v9, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->SUPER_TYPE_KOTLIN_COLLECTIONS_AS_IS:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 165
    .line 166
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 167
    .line 168
    const/16 v14, 0x7d8

    .line 169
    .line 170
    const/4 v15, 0x0

    .line 171
    const/4 v5, 0x1

    .line 172
    const/4 v6, 0x0

    .line 173
    const/4 v9, 0x0

    .line 174
    const/4 v10, 0x0

    .line 175
    const/4 v11, 0x0

    .line 176
    const/4 v13, 0x0

    .line 177
    invoke-direct/range {v2 .. v15}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 178
    .line 179
    .line 180
    sput-object v2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->VALUE_FOR_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 181
    .line 182
    new-instance v3, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 183
    .line 184
    const/16 v15, 0x7bc

    .line 185
    .line 186
    const/16 v16, 0x0

    .line 187
    .line 188
    const/4 v4, 0x1

    .line 189
    const/4 v8, 0x0

    .line 190
    const/4 v9, 0x0

    .line 191
    const/4 v10, 0x1

    .line 192
    const/4 v12, 0x0

    .line 193
    const/4 v14, 0x0

    .line 194
    invoke-direct/range {v3 .. v16}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    .line 195
    .line 196
    .line 197
    sput-object v3, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->INVOKE_DYNAMIC_BOOTSTRAP_ARGUMENT:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 198
    .line 199
    return-void
.end method

.method public constructor <init>()V
    .locals 14

    .line 1
    const/16 v12, 0x7ff

    const/4 v13, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v13}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->needPrimitiveBoxing:Z

    .line 4
    iput-boolean p2, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->needInlineClassWrapping:Z

    .line 5
    iput-boolean p3, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->isForAnnotationParameter:Z

    .line 6
    iput-boolean p4, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->skipDeclarationSiteWildcards:Z

    .line 7
    iput-boolean p5, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->skipDeclarationSiteWildcardsIfPossible:Z

    .line 8
    iput-object p6, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 9
    iput-boolean p7, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->kotlinCollectionsToJavaCollections:Z

    .line 10
    iput-object p8, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericContravariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 11
    iput-object p9, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericInvariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 12
    iput-boolean p10, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->mapTypeAliases:Z

    .line 13
    iput-boolean p11, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->ignoreTypeArgumentsBounds:Z

    return-void
.end method

.method public synthetic constructor <init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZILkotlin/jvm/internal/g;)V
    .locals 2

    and-int/lit8 p13, p12, 0x1

    const/4 v0, 0x1

    if-eqz p13, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p13, p12, 0x2

    if-eqz p13, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p13, p12, 0x4

    const/4 v1, 0x0

    if-eqz p13, :cond_2

    move p3, v1

    :cond_2
    and-int/lit8 p13, p12, 0x8

    if-eqz p13, :cond_3

    move p4, v1

    :cond_3
    and-int/lit8 p13, p12, 0x10

    if-eqz p13, :cond_4

    move p5, v1

    :cond_4
    and-int/lit8 p13, p12, 0x20

    if-eqz p13, :cond_5

    const/4 p6, 0x0

    :cond_5
    and-int/lit8 p13, p12, 0x40

    if-eqz p13, :cond_6

    move p7, v0

    :cond_6
    and-int/lit16 p13, p12, 0x80

    if-eqz p13, :cond_7

    move-object p8, p6

    :cond_7
    and-int/lit16 p13, p12, 0x100

    if-eqz p13, :cond_8

    move-object p9, p6

    :cond_8
    and-int/lit16 p13, p12, 0x200

    if-eqz p13, :cond_9

    move p10, v1

    :cond_9
    and-int/lit16 p12, p12, 0x400

    if-eqz p12, :cond_a

    move p11, v1

    .line 14
    :cond_a
    invoke-direct/range {p0 .. p11}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZ)V

    return-void
.end method


# virtual methods
.method public final getKotlinCollectionsToJavaCollections()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->kotlinCollectionsToJavaCollections:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getMapTypeAliases()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->mapTypeAliases:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getNeedInlineClassWrapping()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->needInlineClassWrapping:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getNeedPrimitiveBoxing()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->needPrimitiveBoxing:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isForAnnotationParameter()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->isForAnnotationParameter:Z

    .line 2
    .line 3
    return p0
.end method

.method public final toGenericArgumentMode(Lkotlin/reflect/jvm/internal/impl/types/Variance;Z)Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;
    .locals 1

    .line 1
    const-string v0, "effectiveVariance"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p2, :cond_0

    .line 7
    .line 8
    iget-boolean p2, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->isForAnnotationParameter:Z

    .line 9
    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    sget-object p2, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    aget p1, p2, p1

    .line 20
    .line 21
    const/4 p2, 0x1

    .line 22
    if-eq p1, p2, :cond_4

    .line 23
    .line 24
    const/4 p2, 0x2

    .line 25
    if-eq p1, p2, :cond_2

    .line 26
    .line 27
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 28
    .line 29
    if-nez p1, :cond_1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    return-object p1

    .line 33
    :cond_2
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericInvariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 34
    .line 35
    if-nez p1, :cond_3

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_3
    return-object p1

    .line 39
    :cond_4
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericContravariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 40
    .line 41
    if-nez p1, :cond_5

    .line 42
    .line 43
    :goto_0
    return-object p0

    .line 44
    :cond_5
    return-object p1
.end method

.method public final wrapInlineClassesMode()Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;
    .locals 12

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 2
    .line 3
    iget-boolean v1, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->needPrimitiveBoxing:Z

    .line 4
    .line 5
    iget-boolean v3, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->isForAnnotationParameter:Z

    .line 6
    .line 7
    iget-boolean v4, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->skipDeclarationSiteWildcards:Z

    .line 8
    .line 9
    iget-boolean v5, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->skipDeclarationSiteWildcardsIfPossible:Z

    .line 10
    .line 11
    iget-object v6, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 12
    .line 13
    iget-boolean v7, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->kotlinCollectionsToJavaCollections:Z

    .line 14
    .line 15
    iget-object v8, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericContravariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 16
    .line 17
    iget-object v9, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->genericInvariantArgumentMode:Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;

    .line 18
    .line 19
    iget-boolean v10, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->mapTypeAliases:Z

    .line 20
    .line 21
    iget-boolean v11, p0, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;->ignoreTypeArgumentsBounds:Z

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-direct/range {v0 .. v11}, Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;-><init>(ZZZZZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZLkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;Lkotlin/reflect/jvm/internal/impl/load/kotlin/TypeMappingMode;ZZ)V

    .line 25
    .line 26
    .line 27
    return-object v0
.end method
