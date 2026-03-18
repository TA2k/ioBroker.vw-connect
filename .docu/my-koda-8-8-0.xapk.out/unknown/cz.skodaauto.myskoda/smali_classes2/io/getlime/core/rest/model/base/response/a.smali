.class public Lio/getlime/core/rest/model/base/response/a;
.super Lio/getlime/core/rest/model/base/response/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/getlime/core/rest/model/base/response/b<",
        "Lio/getlime/core/rest/model/base/entity/a;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    new-instance v0, Lio/getlime/core/rest/model/base/entity/a;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/getlime/core/rest/model/base/entity/a;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lio/getlime/core/rest/model/base/response/b;-><init>(Lio/getlime/core/rest/model/base/entity/a;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method
