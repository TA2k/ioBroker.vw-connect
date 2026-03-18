.class public final Lzd0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lxd0/b;


# direct methods
.method public constructor <init>(Lxd0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzd0/a;->a:Lxd0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lne0/t;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lzd0/a;->a:Lxd0/b;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lxd0/b;->b:Lyy0/i1;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
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
    check-cast v1, Lne0/t;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
