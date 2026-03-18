.class public final La70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:La70/e;


# direct methods
.method public constructor <init>(La70/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La70/a;->a:La70/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object p0, p0, La70/a;->a:La70/e;

    .line 2
    .line 3
    check-cast p0, Liy/b;

    .line 4
    .line 5
    new-instance v0, Lul0/c;

    .line 6
    .line 7
    sget-object v1, Lly/b;->f:Lly/b;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const/16 v5, 0x1e

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method
