.class public final Ls50/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ls50/l;


# direct methods
.method public constructor <init>(Ls50/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls50/y;->a:Ls50/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object p0, p0, Ls50/y;->a:Ls50/l;

    .line 2
    .line 3
    check-cast p0, Liy/b;

    .line 4
    .line 5
    new-instance v0, Lul0/c;

    .line 6
    .line 7
    sget-object v1, Lly/b;->v2:Lly/b;

    .line 8
    .line 9
    sget-object v2, Lly/b;->i:Lly/b;

    .line 10
    .line 11
    sget-object v3, Lly/b;->m2:Lly/b;

    .line 12
    .line 13
    sget-object v4, Lly/b;->t2:Lly/b;

    .line 14
    .line 15
    filled-new-array {v2, v3, v4}, [Lly/b;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    const/16 v5, 0x2c

    .line 24
    .line 25
    const/4 v2, 0x1

    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0
.end method
