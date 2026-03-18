.class public final Lq80/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/k;

.field public final b:Lcr0/b;

.field public final c:Lf80/c;


# direct methods
.method public constructor <init>(Lkf0/k;Lcr0/b;Lf80/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq80/o;->a:Lkf0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lq80/o;->b:Lcr0/b;

    .line 7
    .line 8
    iput-object p3, p0, Lq80/o;->c:Lf80/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lq80/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lq80/n;-><init>(Lq80/o;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    new-instance p0, Lyy0/m1;

    .line 8
    .line 9
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
