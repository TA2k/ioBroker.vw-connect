.class public final enum Lcom/squareup/moshi/JsonReader$Token;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/JsonReader;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Token"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/squareup/moshi/JsonReader$Token;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum d:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum e:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum f:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum g:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum h:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum i:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum j:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum k:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum l:Lcom/squareup/moshi/JsonReader$Token;

.field public static final enum m:Lcom/squareup/moshi/JsonReader$Token;

.field public static final synthetic n:[Lcom/squareup/moshi/JsonReader$Token;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Lcom/squareup/moshi/JsonReader$Token;

    .line 2
    .line 3
    const-string v1, "BEGIN_ARRAY"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/squareup/moshi/JsonReader$Token;->d:Lcom/squareup/moshi/JsonReader$Token;

    .line 10
    .line 11
    new-instance v1, Lcom/squareup/moshi/JsonReader$Token;

    .line 12
    .line 13
    const-string v2, "END_ARRAY"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lcom/squareup/moshi/JsonReader$Token;->e:Lcom/squareup/moshi/JsonReader$Token;

    .line 20
    .line 21
    new-instance v2, Lcom/squareup/moshi/JsonReader$Token;

    .line 22
    .line 23
    const-string v3, "BEGIN_OBJECT"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lcom/squareup/moshi/JsonReader$Token;->f:Lcom/squareup/moshi/JsonReader$Token;

    .line 30
    .line 31
    new-instance v3, Lcom/squareup/moshi/JsonReader$Token;

    .line 32
    .line 33
    const-string v4, "END_OBJECT"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lcom/squareup/moshi/JsonReader$Token;->g:Lcom/squareup/moshi/JsonReader$Token;

    .line 40
    .line 41
    new-instance v4, Lcom/squareup/moshi/JsonReader$Token;

    .line 42
    .line 43
    const-string v5, "NAME"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Lcom/squareup/moshi/JsonReader$Token;->h:Lcom/squareup/moshi/JsonReader$Token;

    .line 50
    .line 51
    new-instance v5, Lcom/squareup/moshi/JsonReader$Token;

    .line 52
    .line 53
    const-string v6, "STRING"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Lcom/squareup/moshi/JsonReader$Token;->i:Lcom/squareup/moshi/JsonReader$Token;

    .line 60
    .line 61
    new-instance v6, Lcom/squareup/moshi/JsonReader$Token;

    .line 62
    .line 63
    const-string v7, "NUMBER"

    .line 64
    .line 65
    const/4 v8, 0x6

    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v6, Lcom/squareup/moshi/JsonReader$Token;->j:Lcom/squareup/moshi/JsonReader$Token;

    .line 70
    .line 71
    new-instance v7, Lcom/squareup/moshi/JsonReader$Token;

    .line 72
    .line 73
    const-string v8, "BOOLEAN"

    .line 74
    .line 75
    const/4 v9, 0x7

    .line 76
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v7, Lcom/squareup/moshi/JsonReader$Token;->k:Lcom/squareup/moshi/JsonReader$Token;

    .line 80
    .line 81
    new-instance v8, Lcom/squareup/moshi/JsonReader$Token;

    .line 82
    .line 83
    const-string v9, "NULL"

    .line 84
    .line 85
    const/16 v10, 0x8

    .line 86
    .line 87
    invoke-direct {v8, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    sput-object v8, Lcom/squareup/moshi/JsonReader$Token;->l:Lcom/squareup/moshi/JsonReader$Token;

    .line 91
    .line 92
    new-instance v9, Lcom/squareup/moshi/JsonReader$Token;

    .line 93
    .line 94
    const-string v10, "END_DOCUMENT"

    .line 95
    .line 96
    const/16 v11, 0x9

    .line 97
    .line 98
    invoke-direct {v9, v10, v11}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    sput-object v9, Lcom/squareup/moshi/JsonReader$Token;->m:Lcom/squareup/moshi/JsonReader$Token;

    .line 102
    .line 103
    filled-new-array/range {v0 .. v9}, [Lcom/squareup/moshi/JsonReader$Token;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    sput-object v0, Lcom/squareup/moshi/JsonReader$Token;->n:[Lcom/squareup/moshi/JsonReader$Token;

    .line 108
    .line 109
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/squareup/moshi/JsonReader$Token;
    .locals 1

    .line 1
    const-class v0, Lcom/squareup/moshi/JsonReader$Token;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/squareup/moshi/JsonReader$Token;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/squareup/moshi/JsonReader$Token;
    .locals 1

    .line 1
    sget-object v0, Lcom/squareup/moshi/JsonReader$Token;->n:[Lcom/squareup/moshi/JsonReader$Token;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/squareup/moshi/JsonReader$Token;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/squareup/moshi/JsonReader$Token;

    .line 8
    .line 9
    return-object v0
.end method
