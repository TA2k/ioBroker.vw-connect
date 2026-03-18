.class public final Lw70/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lw70/q0;


# direct methods
.method public constructor <init>(Lw70/q0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/h0;->a:Lw70/q0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object p0, p0, Lw70/h0;->a:Lw70/q0;

    .line 2
    .line 3
    check-cast p0, Liy/b;

    .line 4
    .line 5
    new-instance v0, Lul0/c;

    .line 6
    .line 7
    sget-object v1, Lly/b;->e3:Lly/b;

    .line 8
    .line 9
    sget-object v3, Lly/b;->d:Lly/b;

    .line 10
    .line 11
    sget-object v2, Lly/b;->f:Lly/b;

    .line 12
    .line 13
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    const/16 v5, 0x28

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
