.class public final Lc8/d;
.super Landroid/database/ContentObserver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/ContentResolver;

.field public final b:Landroid/net/Uri;

.field public final synthetic c:Lc8/f;


# direct methods
.method public constructor <init>(Lc8/f;Landroid/os/Handler;Landroid/content/ContentResolver;Landroid/net/Uri;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc8/d;->c:Lc8/f;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Landroid/database/ContentObserver;-><init>(Landroid/os/Handler;)V

    .line 4
    .line 5
    .line 6
    iput-object p3, p0, Lc8/d;->a:Landroid/content/ContentResolver;

    .line 7
    .line 8
    iput-object p4, p0, Lc8/d;->b:Landroid/net/Uri;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final onChange(Z)V
    .locals 2

    .line 1
    iget-object p0, p0, Lc8/d;->c:Lc8/f;

    .line 2
    .line 3
    iget-object p1, p0, Lc8/f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Landroid/content/Context;

    .line 6
    .line 7
    iget-object v0, p0, Lc8/f;->j:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lt7/c;

    .line 10
    .line 11
    iget-object v1, p0, Lc8/f;->i:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, La0/j;

    .line 14
    .line 15
    invoke-static {p1, v0, v1}, Lc8/b;->c(Landroid/content/Context;Lt7/c;La0/j;)Lc8/b;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, p1}, Lc8/f;->d(Lc8/b;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
