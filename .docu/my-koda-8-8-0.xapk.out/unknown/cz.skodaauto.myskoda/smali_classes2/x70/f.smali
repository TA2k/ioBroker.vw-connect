.class public final enum Lx70/f;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lx70/f;

.field public static final enum e:Lx70/f;

.field public static final enum f:Lx70/f;

.field public static final synthetic g:[Lx70/f;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lx70/f;

    .line 2
    .line 3
    const-string v1, "Appointment"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lx70/f;->d:Lx70/f;

    .line 10
    .line 11
    new-instance v1, Lx70/f;

    .line 12
    .line 13
    const-string v2, "Quotation"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lx70/f;->e:Lx70/f;

    .line 20
    .line 21
    new-instance v2, Lx70/f;

    .line 22
    .line 23
    const-string v3, "SuperCard"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lx70/f;->f:Lx70/f;

    .line 30
    .line 31
    filled-new-array {v0, v1, v2}, [Lx70/f;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lx70/f;->g:[Lx70/f;

    .line 36
    .line 37
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lx70/f;
    .locals 1

    .line 1
    const-class v0, Lx70/f;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lx70/f;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lx70/f;
    .locals 1

    .line 1
    sget-object v0, Lx70/f;->g:[Lx70/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lx70/f;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-ne p0, v0, :cond_0

    .line 12
    .line 13
    const-string p0, "SUPER_CARD"

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance p0, La8/r0;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    const-string p0, "QUOTATION"

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_2
    const-string p0, "APPOINTMENT"

    .line 26
    .line 27
    return-object p0
.end method
