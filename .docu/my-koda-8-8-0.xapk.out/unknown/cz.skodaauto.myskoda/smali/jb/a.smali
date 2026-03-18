.class public final Ljb/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ljb/b;

.field public final synthetic b:Lxy0/x;


# direct methods
.method public constructor <init>(Ljb/b;Lxy0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljb/a;->a:Ljb/b;

    .line 5
    .line 6
    iput-object p2, p0, Ljb/a;->b:Lxy0/x;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ljb/a;->a:Ljb/b;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljb/b;->d(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    new-instance p1, Lib/b;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljb/b;->c()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-direct {p1, v0}, Lib/b;-><init>(I)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    sget-object p1, Lib/a;->a:Lib/a;

    .line 20
    .line 21
    :goto_0
    iget-object p0, p0, Ljb/a;->b:Lxy0/x;

    .line 22
    .line 23
    check-cast p0, Lxy0/w;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    return-void
.end method
