.class public final Lpp0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/b0;


# direct methods
.method public constructor <init>(Lpp0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/g0;->a:Lpp0/b0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lqp0/e;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object p0, p0, Lpp0/g0;->a:Lpp0/b0;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    if-ne v0, v1, :cond_0

    .line 15
    .line 16
    check-cast p0, Lnp0/a;

    .line 17
    .line 18
    iget-object p0, p0, Lnp0/a;->d:Lyy0/l1;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, La8/r0;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    check-cast p0, Lnp0/a;

    .line 28
    .line 29
    iget-object p0, p0, Lnp0/a;->b:Lyy0/l1;

    .line 30
    .line 31
    return-object p0
.end method
