.class public final Lk90/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li90/c;

.field public final b:Lkf0/m;

.field public final c:Lkg0/a;

.field public final d:Lam0/c;

.field public final e:Lkc0/i;


# direct methods
.method public constructor <init>(Li90/c;Lkf0/m;Lkg0/a;Lam0/c;Lkc0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk90/c;->a:Li90/c;

    .line 5
    .line 6
    iput-object p2, p0, Lk90/c;->b:Lkf0/m;

    .line 7
    .line 8
    iput-object p3, p0, Lk90/c;->c:Lkg0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lk90/c;->d:Lam0/c;

    .line 11
    .line 12
    iput-object p5, p0, Lk90/c;->e:Lkc0/i;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lk90/a;

    .line 4
    .line 5
    new-instance v1, Lk90/b;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, v3, p0, v0, v2}, Lk90/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Lyy0/m1;

    .line 13
    .line 14
    invoke-direct {p0, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 15
    .line 16
    .line 17
    return-object p0
.end method
