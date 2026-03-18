.class public final Lom/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbm/k;


# static fields
.field public static final g:Lod0/g;


# instance fields
.field public final a:Lbm/q;

.field public final b:Lmm/n;

.field public final c:Lom/c;

.field public final d:Lay0/k;

.field public final e:Z

.field public final f:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lod0/g;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lod0/g;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lom/f;->g:Lod0/g;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lbm/q;Lmm/n;Lom/c;Lay0/k;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lom/f;->a:Lbm/q;

    .line 5
    .line 6
    iput-object p2, p0, Lom/f;->b:Lmm/n;

    .line 7
    .line 8
    iput-object p3, p0, Lom/f;->c:Lom/c;

    .line 9
    .line 10
    iput-object p4, p0, Lom/f;->d:Lay0/k;

    .line 11
    .line 12
    iput-boolean p5, p0, Lom/f;->e:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lom/f;->f:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lmc/e;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    check-cast p1, Lrx0/c;

    .line 9
    .line 10
    new-instance p0, Ls10/a0;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    const/16 v2, 0x15

    .line 14
    .line 15
    invoke-direct {p0, v0, v1, v2}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 19
    .line 20
    invoke-static {v0, p0, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method
