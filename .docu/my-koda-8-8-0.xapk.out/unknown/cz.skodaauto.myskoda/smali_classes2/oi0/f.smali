.class public final Loi0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Loi0/d;

.field public final b:Loi0/g;


# direct methods
.method public constructor <init>(Loi0/d;Loi0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Loi0/f;->a:Loi0/d;

    .line 5
    .line 6
    iput-object p2, p0, Loi0/f;->b:Loi0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lpi0/b;)V
    .locals 1

    .line 1
    iget-object v0, p0, Loi0/f;->b:Loi0/g;

    .line 2
    .line 3
    iget-object v0, v0, Loi0/g;->a:Loi0/e;

    .line 4
    .line 5
    check-cast v0, Lmi0/a;

    .line 6
    .line 7
    iput-object p1, v0, Lmi0/a;->b:Lpi0/b;

    .line 8
    .line 9
    iget-object p0, p0, Loi0/f;->a:Loi0/d;

    .line 10
    .line 11
    check-cast p0, Liy/b;

    .line 12
    .line 13
    sget-object p1, Lly/b;->B3:Lly/b;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 16
    .line 17
    .line 18
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
    check-cast v1, Lpi0/b;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Loi0/f;->a(Lpi0/b;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
