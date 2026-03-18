.class public final Ljr0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ljr0/e;

.field public final b:Ljr0/d;

.field public final c:Ljr0/a;

.field public final d:Lkf0/m;


# direct methods
.method public constructor <init>(Ljr0/e;Ljr0/d;Ljr0/a;Lkf0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljr0/c;->a:Ljr0/e;

    .line 5
    .line 6
    iput-object p2, p0, Ljr0/c;->b:Ljr0/d;

    .line 7
    .line 8
    iput-object p3, p0, Ljr0/c;->c:Ljr0/a;

    .line 9
    .line 10
    iput-object p4, p0, Ljr0/c;->d:Lkf0/m;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lkr0/b;)V
    .locals 3

    .line 1
    sget-object v0, Lge0/a;->d:Lge0/a;

    .line 2
    .line 3
    new-instance v1, Ljr0/b;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, p1, v2}, Ljr0/b;-><init>(Ljr0/c;Lkr0/b;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x3

    .line 10
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 11
    .line 12
    .line 13
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
    check-cast v1, Lkr0/b;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ljr0/c;->a(Lkr0/b;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
