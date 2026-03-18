.class public final Lp60/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lp60/d0;


# direct methods
.method public constructor <init>(Lp60/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/a0;->a:Lp60/d0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object p0, p0, Lp60/a0;->a:Lp60/d0;

    .line 2
    .line 3
    check-cast p0, Liy/b;

    .line 4
    .line 5
    new-instance v0, Lul0/c;

    .line 6
    .line 7
    sget-object v1, Lly/b;->G2:Lly/b;

    .line 8
    .line 9
    sget-object v3, Lly/b;->e:Lly/b;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    const/16 v5, 0x38

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method
