.class public final Ly1/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements La2/l;


# instance fields
.field public final a:Landroid/view/View;

.field public final b:Lay0/k;

.field public final c:Lay0/a;

.field public final d:Le1/b1;

.field public final e:Lv2/r;

.field public final f:Ly1/a;

.field public final g:Ly1/a;

.field public h:Landroid/view/ActionMode;

.field public i:La8/y0;


# direct methods
.method public constructor <init>(Landroid/view/View;Lay0/k;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly1/f;->a:Landroid/view/View;

    .line 5
    .line 6
    iput-object p2, p0, Ly1/f;->b:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Ly1/f;->c:Lay0/a;

    .line 9
    .line 10
    new-instance p1, Le1/b1;

    .line 11
    .line 12
    invoke-direct {p1}, Le1/b1;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ly1/f;->d:Le1/b1;

    .line 16
    .line 17
    new-instance p1, Lv2/r;

    .line 18
    .line 19
    new-instance p2, Ly1/a;

    .line 20
    .line 21
    const/4 p3, 0x0

    .line 22
    invoke-direct {p2, p0, p3}, Ly1/a;-><init>(Ly1/f;I)V

    .line 23
    .line 24
    .line 25
    invoke-direct {p1, p2}, Lv2/r;-><init>(Lay0/k;)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Ly1/f;->e:Lv2/r;

    .line 29
    .line 30
    new-instance p1, Ly1/a;

    .line 31
    .line 32
    const/4 p2, 0x1

    .line 33
    invoke-direct {p1, p0, p2}, Ly1/a;-><init>(Ly1/f;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Ly1/f;->f:Ly1/a;

    .line 37
    .line 38
    new-instance p1, Ly1/a;

    .line 39
    .line 40
    const/4 p2, 0x2

    .line 41
    invoke-direct {p1, p0, p2}, Ly1/a;-><init>(Ly1/f;I)V

    .line 42
    .line 43
    .line 44
    iput-object p1, p0, Ly1/f;->g:Ly1/a;

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final a(La2/k;Lrx0/i;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lxf0/f2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, v2, p0, p1, v1}, Lxf0/f2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Ly1/f;->d:Le1/b1;

    .line 9
    .line 10
    invoke-static {p0, v0, p2}, Le1/b1;->b(Le1/b1;Lay0/k;Lrx0/i;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
