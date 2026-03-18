.class public abstract Lkj0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lxy0/j;

.field public static final b:Lxy0/j;

.field public static final c:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x6

    .line 3
    const v2, 0x7fffffff

    .line 4
    .line 5
    .line 6
    invoke-static {v2, v1, v0}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lkj0/a;->a:Lxy0/j;

    .line 11
    .line 12
    sput-object v0, Lkj0/a;->b:Lxy0/j;

    .line 13
    .line 14
    sget-object v0, Lkj0/e;->f:Lkj0/e;

    .line 15
    .line 16
    sget-object v1, Lkj0/e;->g:Lkj0/e;

    .line 17
    .line 18
    sget-object v2, Lkj0/e;->h:Lkj0/e;

    .line 19
    .line 20
    filled-new-array {v0, v1, v2}, [Lkj0/e;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sput-object v0, Lkj0/a;->c:Ljava/util/List;

    .line 29
    .line 30
    return-void
.end method
