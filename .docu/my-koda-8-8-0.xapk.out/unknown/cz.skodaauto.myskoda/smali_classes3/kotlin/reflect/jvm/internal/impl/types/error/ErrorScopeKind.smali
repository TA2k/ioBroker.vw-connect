.class public final enum Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum CAPTURED_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum ERASED_RECEIVER_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum ERROR_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum INTEGER_LITERAL_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum NON_CLASSIFIER_SUPER_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum SCOPE_FOR_ABBREVIATION_TYPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum SCOPE_FOR_ERROR_CLASS:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum SCOPE_FOR_ERROR_RESOLUTION_CANDIDATE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum STUB_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

.field public static final enum UNSUPPORTED_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;


# instance fields
.field private final debugMessage:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;
    .locals 10

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->CAPTURED_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->INTEGER_LITERAL_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 4
    .line 5
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->ERASED_RECEIVER_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 6
    .line 7
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->SCOPE_FOR_ABBREVIATION_TYPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 8
    .line 9
    sget-object v4, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->STUB_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 10
    .line 11
    sget-object v5, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->NON_CLASSIFIER_SUPER_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 12
    .line 13
    sget-object v6, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->ERROR_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 14
    .line 15
    sget-object v7, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->UNSUPPORTED_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 16
    .line 17
    sget-object v8, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->SCOPE_FOR_ERROR_CLASS:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 18
    .line 19
    sget-object v9, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->SCOPE_FOR_ERROR_RESOLUTION_CANDIDATE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 20
    .line 21
    filled-new-array/range {v0 .. v9}, [Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "No member resolution should be done on captured type, it used only during constraint system resolution"

    .line 5
    .line 6
    const-string v3, "CAPTURED_TYPE_SCOPE"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->CAPTURED_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 12
    .line 13
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    const-string v2, "Scope for integer literal type (%s)"

    .line 17
    .line 18
    const-string v3, "INTEGER_LITERAL_TYPE_SCOPE"

    .line 19
    .line 20
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->INTEGER_LITERAL_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 24
    .line 25
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    const-string v2, "Error scope for erased receiver type"

    .line 29
    .line 30
    const-string v3, "ERASED_RECEIVER_TYPE_SCOPE"

    .line 31
    .line 32
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->ERASED_RECEIVER_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 36
    .line 37
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 38
    .line 39
    const/4 v1, 0x3

    .line 40
    const-string v2, "Scope for abbreviation %s"

    .line 41
    .line 42
    const-string v3, "SCOPE_FOR_ABBREVIATION_TYPE"

    .line 43
    .line 44
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->SCOPE_FOR_ABBREVIATION_TYPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 48
    .line 49
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 50
    .line 51
    const/4 v1, 0x4

    .line 52
    const-string v2, "Scope for stub type %s"

    .line 53
    .line 54
    const-string v3, "STUB_TYPE_SCOPE"

    .line 55
    .line 56
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->STUB_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 60
    .line 61
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 62
    .line 63
    const/4 v1, 0x5

    .line 64
    const-string v2, "A scope for common supertype which is not a normal classifier"

    .line 65
    .line 66
    const-string v3, "NON_CLASSIFIER_SUPER_TYPE_SCOPE"

    .line 67
    .line 68
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->NON_CLASSIFIER_SUPER_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 72
    .line 73
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 74
    .line 75
    const/4 v1, 0x6

    .line 76
    const-string v2, "Scope for error type %s"

    .line 77
    .line 78
    const-string v3, "ERROR_TYPE_SCOPE"

    .line 79
    .line 80
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 81
    .line 82
    .line 83
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->ERROR_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 84
    .line 85
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 86
    .line 87
    const/4 v1, 0x7

    .line 88
    const-string v2, "Scope for unsupported type %s"

    .line 89
    .line 90
    const-string v3, "UNSUPPORTED_TYPE_SCOPE"

    .line 91
    .line 92
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->UNSUPPORTED_TYPE_SCOPE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 96
    .line 97
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 98
    .line 99
    const/16 v1, 0x8

    .line 100
    .line 101
    const-string v2, "Error scope for class %s with arguments: %s"

    .line 102
    .line 103
    const-string v3, "SCOPE_FOR_ERROR_CLASS"

    .line 104
    .line 105
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 106
    .line 107
    .line 108
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->SCOPE_FOR_ERROR_CLASS:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 109
    .line 110
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 111
    .line 112
    const/16 v1, 0x9

    .line 113
    .line 114
    const-string v2, "Error resolution candidate for call %s"

    .line 115
    .line 116
    const-string v3, "SCOPE_FOR_ERROR_RESOLUTION_CANDIDATE"

    .line 117
    .line 118
    invoke-direct {v0, v3, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 119
    .line 120
    .line 121
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->SCOPE_FOR_ERROR_RESOLUTION_CANDIDATE:Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 122
    .line 123
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->$values()[Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->$VALUES:[Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 128
    .line 129
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->$ENTRIES:Lsx0/a;

    .line 134
    .line 135
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->debugMessage:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;
    .locals 1

    .line 1
    const-class v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->$VALUES:[Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getDebugMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/types/error/ErrorScopeKind;->debugMessage:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
