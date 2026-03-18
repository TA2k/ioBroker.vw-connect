.class public final Lov/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llp/u;)V
    .locals 1

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 10
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    iput-object p1, p0, Lov/d;->a:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llp/wg;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 2
    iget-object v1, p1, Llp/wg;->d:Ljava/lang/String;

    .line 3
    iput-object v1, p0, Lov/d;->a:Ljava/lang/String;

    .line 4
    iget-object p0, p1, Llp/wg;->e:Ljava/util/List;

    .line 5
    new-instance p1, Lip/v;

    const/16 v1, 0xb

    .line 6
    invoke-direct {p1, v1}, Lip/v;-><init>(I)V

    .line 7
    invoke-static {p0, p1}, Llp/cg;->d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;

    move-result-object p0

    .line 8
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    return-void
.end method
