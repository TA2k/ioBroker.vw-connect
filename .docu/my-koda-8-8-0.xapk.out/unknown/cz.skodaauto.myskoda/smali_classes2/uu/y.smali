.class public final Luu/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luu/s0;


# instance fields
.field public final a:Lqp/g;

.field public final b:Lay0/n;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lqp/g;Lay0/n;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "map"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "setter"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "listener"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Luu/y;->a:Lqp/g;

    .line 20
    .line 21
    iput-object p2, p0, Luu/y;->b:Lay0/n;

    .line 22
    .line 23
    iput-object p3, p0, Luu/y;->c:Ljava/lang/Object;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Luu/y;->b:Lay0/n;

    .line 2
    .line 3
    iget-object v1, p0, Luu/y;->a:Lqp/g;

    .line 4
    .line 5
    iget-object p0, p0, Luu/y;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-interface {v0, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object v0, p0, Luu/y;->b:Lay0/n;

    .line 2
    .line 3
    iget-object p0, p0, Luu/y;->a:Lqp/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-interface {v0, p0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final d()V
    .locals 2

    .line 1
    iget-object v0, p0, Luu/y;->b:Lay0/n;

    .line 2
    .line 3
    iget-object p0, p0, Luu/y;->a:Lqp/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-interface {v0, p0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    return-void
.end method
