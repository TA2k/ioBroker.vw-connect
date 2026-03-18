.class public final Lrz/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lrz/a;

.field public final b:Lqd0/y0;


# direct methods
.method public constructor <init>(Lrz/a;Lqd0/y0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrz/u;->a:Lrz/a;

    .line 5
    .line 6
    iput-object p2, p0, Lrz/u;->b:Lqd0/y0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lrd0/r;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lrz/u;->b:Lqd0/y0;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lqd0/y0;->a(Lrd0/r;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lrz/u;->a:Lrz/a;

    .line 12
    .line 13
    check-cast p0, Liy/b;

    .line 14
    .line 15
    sget-object p1, Lly/b;->q:Lly/b;

    .line 16
    .line 17
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 18
    .line 19
    .line 20
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
    check-cast v1, Lrd0/r;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lrz/u;->a(Lrd0/r;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
