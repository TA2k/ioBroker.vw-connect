.class public final Lb/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/window/OnBackAnimationCallback;


# instance fields
.field public final synthetic a:Lb/b0;

.field public final synthetic b:Lb/b0;

.field public final synthetic c:Lb/c0;

.field public final synthetic d:Lb/c0;


# direct methods
.method public constructor <init>(Lb/b0;Lb/b0;Lb/c0;Lb/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb/e0;->a:Lb/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lb/e0;->b:Lb/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lb/e0;->c:Lb/c0;

    .line 9
    .line 10
    iput-object p4, p0, Lb/e0;->d:Lb/c0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final onBackCancelled()V
    .locals 0

    .line 1
    iget-object p0, p0, Lb/e0;->d:Lb/c0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/c0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onBackInvoked()V
    .locals 0

    .line 1
    iget-object p0, p0, Lb/e0;->c:Lb/c0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/c0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onBackProgressed(Landroid/window/BackEvent;)V
    .locals 1

    .line 1
    const-string v0, "backEvent"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb/c;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lb/c;-><init>(Landroid/window/BackEvent;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lb/e0;->b:Lb/b0;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lb/b0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final onBackStarted(Landroid/window/BackEvent;)V
    .locals 1

    .line 1
    const-string v0, "backEvent"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb/c;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lb/c;-><init>(Landroid/window/BackEvent;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lb/e0;->a:Lb/b0;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lb/b0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-void
.end method
