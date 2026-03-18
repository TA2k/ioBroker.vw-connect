.class public Lcom/google/android/datatransport/cct/CctBackendFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public create(Lsn/c;)Lsn/e;
    .locals 2

    .line 1
    new-instance p0, Lpn/b;

    .line 2
    .line 3
    check-cast p1, Lsn/b;

    .line 4
    .line 5
    iget-object v0, p1, Lsn/b;->a:Landroid/content/Context;

    .line 6
    .line 7
    iget-object v1, p1, Lsn/b;->b:Lao/a;

    .line 8
    .line 9
    iget-object p1, p1, Lsn/b;->c:Lao/a;

    .line 10
    .line 11
    invoke-direct {p0, v0, v1, p1}, Lpn/b;-><init>(Landroid/content/Context;Lao/a;Lao/a;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
