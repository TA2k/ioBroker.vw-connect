.class public final Lw70/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lw70/q0;

.field public final b:Lal0/m1;


# direct methods
.method public constructor <init>(Lw70/q0;Lal0/m1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/c0;->a:Lw70/q0;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/c0;->b:Lal0/m1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lcq0/n;)V
    .locals 7

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lbl0/k0;

    .line 7
    .line 8
    iget-object v1, p1, Lcq0/n;->a:Ljava/lang/String;

    .line 9
    .line 10
    new-instance v2, Lxj0/f;

    .line 11
    .line 12
    iget-object p1, p1, Lcq0/n;->e:Lcq0/t;

    .line 13
    .line 14
    iget-wide v3, p1, Lcq0/t;->a:D

    .line 15
    .line 16
    iget-wide v5, p1, Lcq0/t;->b:D

    .line 17
    .line 18
    invoke-direct {v2, v3, v4, v5, v6}, Lxj0/f;-><init>(DD)V

    .line 19
    .line 20
    .line 21
    invoke-direct {v0, v1, v2}, Lbl0/k0;-><init>(Ljava/lang/String;Lxj0/f;)V

    .line 22
    .line 23
    .line 24
    iget-object p1, p0, Lw70/c0;->b:Lal0/m1;

    .line 25
    .line 26
    invoke-virtual {p1, v0}, Lal0/m1;->a(Lbl0/j0;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lw70/c0;->a:Lw70/q0;

    .line 30
    .line 31
    check-cast p0, Liy/b;

    .line 32
    .line 33
    invoke-virtual {p0}, Liy/b;->h()V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcq0/n;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lw70/c0;->a(Lcq0/n;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
