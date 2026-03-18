.class public final Lkn/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:Lkn/c0;

.field public final synthetic g:Lkn/l0;

.field public final synthetic h:Z

.field public final synthetic i:F


# direct methods
.method public constructor <init>(Lkn/c0;Lkn/l0;ZF)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkn/e;->f:Lkn/c0;

    .line 2
    .line 3
    iput-object p2, p0, Lkn/e;->g:Lkn/l0;

    .line 4
    .line 5
    iput-boolean p3, p0, Lkn/e;->h:Z

    .line 6
    .line 7
    iput p4, p0, Lkn/e;->i:F

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lkn/e;->f:Lkn/c0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v1, "<set-?>"

    .line 7
    .line 8
    iget-object v2, p0, Lkn/e;->g:Lkn/l0;

    .line 9
    .line 10
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iput-object v2, v0, Lkn/c0;->l:Lkn/l0;

    .line 14
    .line 15
    iget-boolean v1, p0, Lkn/e;->h:Z

    .line 16
    .line 17
    iput-boolean v1, v0, Lkn/c0;->m:Z

    .line 18
    .line 19
    iget p0, p0, Lkn/e;->i:F

    .line 20
    .line 21
    iput p0, v0, Lkn/c0;->d:F

    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0
.end method
