.class public final Lh7/q;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/z;


# instance fields
.field public final synthetic d:Lh7/a0;

.field public final synthetic e:La7/n;

.field public final synthetic f:Landroid/content/Context;


# direct methods
.method public constructor <init>(Lh7/a0;La7/n;Landroid/content/Context;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh7/q;->d:Lh7/a0;

    .line 2
    .line 3
    iput-object p2, p0, Lh7/q;->e:La7/n;

    .line 4
    .line 5
    iput-object p3, p0, Lh7/q;->f:Landroid/content/Context;

    .line 6
    .line 7
    sget-object p1, Lvy0/y;->d:Lvy0/y;

    .line 8
    .line 9
    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final handleException(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 6

    .line 1
    new-instance v0, La7/k;

    .line 2
    .line 3
    iget-object v2, p0, Lh7/q;->f:Landroid/content/Context;

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    iget-object v1, p0, Lh7/q;->e:La7/n;

    .line 7
    .line 8
    iget-object v4, p0, Lh7/q;->d:Lh7/a0;

    .line 9
    .line 10
    move-object v3, p2

    .line 11
    invoke-direct/range {v0 .. v5}, La7/k;-><init>(La7/n;Landroid/content/Context;Ljava/lang/Throwable;Lh7/a0;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    const/4 p0, 0x3

    .line 15
    const/4 p1, 0x0

    .line 16
    invoke-static {v4, p1, p1, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 17
    .line 18
    .line 19
    return-void
.end method
