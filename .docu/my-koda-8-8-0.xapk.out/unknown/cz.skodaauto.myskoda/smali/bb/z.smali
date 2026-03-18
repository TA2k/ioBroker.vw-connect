.class public final Lbb/z;
.super Lbb/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Landroidx/collection/f;

.field public final synthetic b:Lbb/a0;


# direct methods
.method public constructor <init>(Lbb/a0;Landroidx/collection/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbb/z;->b:Lbb/a0;

    .line 5
    .line 6
    iput-object p2, p0, Lbb/z;->a:Landroidx/collection/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c(Lbb/x;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lbb/z;->b:Lbb/a0;

    .line 2
    .line 3
    iget-object v0, v0, Lbb/a0;->e:Landroid/view/ViewGroup;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/z;->a:Landroidx/collection/f;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p0}, Lbb/x;->B(Lbb/v;)Lbb/x;

    .line 17
    .line 18
    .line 19
    return-void
.end method
