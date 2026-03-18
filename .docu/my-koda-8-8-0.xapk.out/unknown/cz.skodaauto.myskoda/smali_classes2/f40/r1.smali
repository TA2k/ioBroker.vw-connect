.class public final Lf40/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/f1;

.field public final b:Lf40/y0;


# direct methods
.method public constructor <init>(Lf40/f1;Lf40/y0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/r1;->a:Lf40/f1;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/r1;->b:Lf40/y0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lg40/v0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lf40/r1;->b:Lf40/y0;

    .line 2
    .line 3
    check-cast v0, Ld40/a;

    .line 4
    .line 5
    iput-object p1, v0, Ld40/a;->c:Lg40/v0;

    .line 6
    .line 7
    iget-object p1, v0, Ld40/a;->b:Lwe0/a;

    .line 8
    .line 9
    check-cast p1, Lwe0/c;

    .line 10
    .line 11
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lf40/r1;->a:Lf40/f1;

    .line 15
    .line 16
    check-cast p0, Liy/b;

    .line 17
    .line 18
    sget-object p1, Lly/b;->r4:Lly/b;

    .line 19
    .line 20
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 21
    .line 22
    .line 23
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
    check-cast v1, Lg40/v0;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lf40/r1;->a(Lg40/v0;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
