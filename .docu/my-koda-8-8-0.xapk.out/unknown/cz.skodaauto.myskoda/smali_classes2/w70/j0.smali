.class public final Lw70/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/t;

.field public final b:Lw70/q0;

.field public final c:Lbq0/h;


# direct methods
.method public constructor <init>(Lbq0/t;Lw70/q0;Lbq0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/j0;->a:Lbq0/t;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/j0;->b:Lw70/q0;

    .line 7
    .line 8
    iput-object p3, p0, Lw70/j0;->c:Lbq0/h;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lcq0/n;)V
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lne0/e;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lw70/j0;->c:Lbq0/h;

    .line 12
    .line 13
    check-cast v1, Lzp0/c;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Lzp0/c;->c(Lne0/s;)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Lcq0/o;

    .line 19
    .line 20
    invoke-direct {v0, p1}, Lcq0/o;-><init>(Lcq0/n;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lw70/j0;->a:Lbq0/t;

    .line 24
    .line 25
    iget-object p1, p1, Lbq0/t;->a:Lbq0/h;

    .line 26
    .line 27
    check-cast p1, Lzp0/c;

    .line 28
    .line 29
    iput-object v0, p1, Lzp0/c;->f:Lcq0/q;

    .line 30
    .line 31
    iget-object p0, p0, Lw70/j0;->b:Lw70/q0;

    .line 32
    .line 33
    check-cast p0, Liy/b;

    .line 34
    .line 35
    sget-object p1, Lly/b;->j3:Lly/b;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 38
    .line 39
    .line 40
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
    invoke-virtual {p0, v1}, Lw70/j0;->a(Lcq0/n;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
