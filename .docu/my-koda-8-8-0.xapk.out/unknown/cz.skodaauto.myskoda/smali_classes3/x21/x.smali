.class public final Lx21/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lm1/m;

.field public final synthetic b:Lg1/w1;


# direct methods
.method public constructor <init>(Lm1/m;Lg1/w1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx21/x;->a:Lm1/m;

    .line 5
    .line 6
    iput-object p2, p0, Lx21/x;->b:Lg1/w1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lx21/x;->a:Lm1/m;

    .line 2
    .line 3
    iget p0, p0, Lm1/m;->a:I

    .line 4
    .line 5
    return p0
.end method

.method public final b()J
    .locals 2

    .line 1
    iget-object v0, p0, Lx21/x;->a:Lm1/m;

    .line 2
    .line 3
    iget v0, v0, Lm1/m;->o:I

    .line 4
    .line 5
    iget-object p0, p0, Lx21/x;->b:Lg1/w1;

    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/ee;->b(Lg1/w1;I)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    return-wide v0
.end method

.method public final c()J
    .locals 3

    .line 1
    iget-object v0, p0, Lx21/x;->a:Lm1/m;

    .line 2
    .line 3
    iget v0, v0, Lm1/m;->p:I

    .line 4
    .line 5
    const-string v1, "orientation"

    .line 6
    .line 7
    iget-object p0, p0, Lx21/x;->b:Lg1/w1;

    .line 8
    .line 9
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    const/4 v1, 0x0

    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    if-ne p0, v2, :cond_0

    .line 21
    .line 22
    invoke-static {v0, v1}, Lkp/f9;->a(II)J

    .line 23
    .line 24
    .line 25
    move-result-wide v0

    .line 26
    return-wide v0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {v1, v0}, Lkp/f9;->a(II)J

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    return-wide v0
.end method
