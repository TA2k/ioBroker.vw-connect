.class public final Lpp0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/c0;

.field public final b:Lpp0/b0;


# direct methods
.method public constructor <init>(Lpp0/c0;Lpp0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/g;->a:Lpp0/c0;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/g;->b:Lpp0/b0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lpp0/g;->a:Lpp0/c0;

    .line 2
    .line 3
    check-cast v0, Lnp0/b;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, v1}, Lnp0/b;->a(Lqp0/o;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, v0, Lnp0/b;->b:Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lpp0/g;->b:Lpp0/b0;

    .line 15
    .line 16
    check-cast p0, Lnp0/a;

    .line 17
    .line 18
    iget-object v0, p0, Lnp0/a;->a:Lyy0/c2;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lnp0/a;->c:Lyy0/c2;

    .line 24
    .line 25
    invoke-virtual {p0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
