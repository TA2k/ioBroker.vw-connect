.class public final Lr2/b;
.super Lmx0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo2/b;


# static fields
.field public static final g:Lr2/b;


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Lq2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lr2/b;

    .line 2
    .line 3
    sget-object v1, Ls2/b;->a:Ls2/b;

    .line 4
    .line 5
    sget-object v2, Lq2/b;->f:Lq2/b;

    .line 6
    .line 7
    invoke-direct {v0, v1, v1, v2}, Lr2/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lq2/b;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lr2/b;->g:Lr2/b;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Lq2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr2/b;->d:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Lr2/b;->e:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Lr2/b;->f:Lq2/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lr2/b;->f:Lq2/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lq2/b;->c()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lr2/b;->f:Lq2/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lq2/b;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    .line 1
    new-instance v0, Lr2/c;

    .line 2
    .line 3
    iget-object v1, p0, Lr2/b;->f:Lq2/b;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object p0, p0, Lr2/b;->d:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-direct {v0, p0, v1, v2}, Lr2/c;-><init>(Ljava/lang/Object;Ljava/util/Map;I)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
