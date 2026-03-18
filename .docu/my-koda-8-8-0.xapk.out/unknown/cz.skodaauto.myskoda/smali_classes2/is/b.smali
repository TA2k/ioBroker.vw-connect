.class public final Lis/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public volatile b:Ljava/lang/Object;

.field public volatile c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/os/Looper;Ljava/lang/Object;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Lj0/e;

    invoke-direct {v0, p1}, Lj0/e;-><init>(Landroid/os/Looper;)V

    iput-object v0, p0, Lis/b;->a:Ljava/lang/Object;

    const-string p1, "Listener must not be null"

    .line 2
    invoke-static {p2, p1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p2, p0, Lis/b;->b:Ljava/lang/Object;

    new-instance p1, Llo/k;

    .line 3
    invoke-static {p3}, Lno/c0;->e(Ljava/lang/String;)V

    invoke-direct {p1, p2, p3}, Llo/k;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Lis/b;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lgs/q;)V
    .locals 3

    .line 4
    new-instance v0, Lls/b;

    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    new-instance v1, Lpy/a;

    const/16 v2, 0x8

    .line 7
    invoke-direct {v1, v2}, Lpy/a;-><init>(I)V

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object v0, p0, Lis/b;->c:Ljava/lang/Object;

    .line 10
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lis/b;->a:Ljava/lang/Object;

    .line 11
    iput-object v1, p0, Lis/b;->b:Ljava/lang/Object;

    .line 12
    new-instance v0, Lis/a;

    invoke-direct {v0, p0}, Lis/a;-><init>(Lis/b;)V

    invoke-virtual {p1, v0}, Lgs/q;->a(Lgt/a;)V

    return-void
.end method

.method public constructor <init>(Ls6/h;)V
    .locals 0

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    iput-object p1, p0, Lis/b;->a:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Llo/l;)V
    .locals 2

    .line 1
    new-instance v0, Llr/b;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1, p0, p1}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lis/b;->a:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lj0/e;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lj0/e;->execute(Ljava/lang/Runnable;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
