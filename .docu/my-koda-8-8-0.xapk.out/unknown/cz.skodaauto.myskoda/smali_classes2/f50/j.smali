.class public final Lf50/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf50/n;

.field public final b:Lpp0/l1;


# direct methods
.method public constructor <init>(Lf50/n;Lpp0/l1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/j;->a:Lf50/n;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/j;->b:Lpp0/l1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lqp0/o;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lf50/j;->b:Lpp0/l1;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lpp0/l1;->a(Lqp0/o;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lf50/j;->a:Lf50/n;

    .line 7
    .line 8
    check-cast p0, Liy/b;

    .line 9
    .line 10
    new-instance v0, Lul0/c;

    .line 11
    .line 12
    sget-object v1, Lly/b;->V1:Lly/b;

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/16 v5, 0x32

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    move-object v3, v1

    .line 19
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 23
    .line 24
    .line 25
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
    check-cast v1, Lqp0/o;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lf50/j;->a(Lqp0/o;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
