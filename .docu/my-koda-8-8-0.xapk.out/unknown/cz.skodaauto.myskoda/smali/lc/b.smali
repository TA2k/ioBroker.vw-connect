.class public final enum Llc/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Llc/b;

.field public static final enum f:Llc/b;

.field public static final enum g:Llc/b;

.field public static final synthetic h:[Llc/b;

.field public static final synthetic i:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Llc/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    const-string v3, "Cancel"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Llc/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Llc/b;->e:Llc/b;

    .line 12
    .line 13
    new-instance v1, Llc/b;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "retry"

    .line 17
    .line 18
    const-string v4, "Retry"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Llc/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Llc/b;->f:Llc/b;

    .line 24
    .line 25
    new-instance v2, Llc/b;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const-string v4, "setupPayment"

    .line 29
    .line 30
    const-string v5, "SetupPayment"

    .line 31
    .line 32
    invoke-direct {v2, v5, v3, v4}, Llc/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Llc/b;->g:Llc/b;

    .line 36
    .line 37
    filled-new-array {v0, v1, v2}, [Llc/b;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Llc/b;->h:[Llc/b;

    .line 42
    .line 43
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Llc/b;->i:Lsx0/b;

    .line 48
    .line 49
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Llc/b;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llc/b;
    .locals 1

    .line 1
    const-class v0, Llc/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Llc/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Llc/b;
    .locals 1

    .line 1
    sget-object v0, Llc/b;->h:[Llc/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Llc/b;

    .line 8
    .line 9
    return-object v0
.end method
