.class public final enum Lqr/h;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/crypto/tink/shaded/protobuf/z;


# static fields
.field public static final enum d:Lqr/h;

.field public static final enum e:Lqr/h;

.field public static final enum f:Lqr/h;

.field public static final enum g:Lqr/h;

.field public static final enum h:Lqr/h;

.field public static final enum i:Lqr/h;

.field public static final synthetic j:[Lqr/h;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lqr/h;

    .line 2
    .line 3
    const-string v1, "UNKNOWN_HASH"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lqr/h;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lqr/h;->d:Lqr/h;

    .line 10
    .line 11
    new-instance v1, Lqr/h;

    .line 12
    .line 13
    const-string v2, "SHA1"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3, v3}, Lqr/h;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lqr/h;->e:Lqr/h;

    .line 20
    .line 21
    new-instance v2, Lqr/h;

    .line 22
    .line 23
    const-string v3, "SHA384"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4, v4}, Lqr/h;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lqr/h;->f:Lqr/h;

    .line 30
    .line 31
    new-instance v3, Lqr/h;

    .line 32
    .line 33
    const-string v4, "SHA256"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5, v5}, Lqr/h;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lqr/h;->g:Lqr/h;

    .line 40
    .line 41
    new-instance v4, Lqr/h;

    .line 42
    .line 43
    const-string v5, "SHA512"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6, v6}, Lqr/h;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Lqr/h;->h:Lqr/h;

    .line 50
    .line 51
    new-instance v5, Lqr/h;

    .line 52
    .line 53
    const/4 v6, 0x5

    .line 54
    const/4 v7, -0x1

    .line 55
    const-string v8, "UNRECOGNIZED"

    .line 56
    .line 57
    invoke-direct {v5, v8, v6, v7}, Lqr/h;-><init>(Ljava/lang/String;II)V

    .line 58
    .line 59
    .line 60
    sput-object v5, Lqr/h;->i:Lqr/h;

    .line 61
    .line 62
    filled-new-array/range {v0 .. v5}, [Lqr/h;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Lqr/h;->j:[Lqr/h;

    .line 67
    .line 68
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqr/h;
    .locals 1

    .line 1
    const-class v0, Lqr/h;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqr/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqr/h;
    .locals 1

    .line 1
    sget-object v0, Lqr/h;->j:[Lqr/h;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lqr/h;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqr/h;

    .line 8
    .line 9
    return-object v0
.end method
