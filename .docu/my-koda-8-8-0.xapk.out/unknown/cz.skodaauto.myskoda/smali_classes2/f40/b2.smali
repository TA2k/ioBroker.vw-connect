.class public final Lf40/b2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/f1;

.field public final b:Lf40/n0;


# direct methods
.method public constructor <init>(Lf40/f1;Lf40/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/b2;->a:Lf40/f1;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/b2;->b:Lf40/n0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lf40/b2;->b:Lf40/n0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lf40/n0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lf40/b2;->a:Lf40/f1;

    .line 7
    .line 8
    check-cast p0, Liy/b;

    .line 9
    .line 10
    new-instance v0, Lul0/c;

    .line 11
    .line 12
    sget-object v1, Lly/b;->j4:Lly/b;

    .line 13
    .line 14
    sget-object v3, Lly/b;->q4:Lly/b;

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    const/16 v5, 0x38

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method
