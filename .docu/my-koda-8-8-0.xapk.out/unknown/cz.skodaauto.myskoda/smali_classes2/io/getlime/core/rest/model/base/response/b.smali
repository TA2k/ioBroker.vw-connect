.class public Lio/getlime/core/rest/model/base/response/b;
.super Lio/getlime/core/rest/model/base/response/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lio/getlime/core/rest/model/base/response/c;"
    }
.end annotation


# instance fields
.field private responseObject:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TT;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/getlime/core/rest/model/base/response/c;-><init>()V

    .line 2
    const-string v0, "OK"

    iput-object v0, p0, Lio/getlime/core/rest/model/base/response/c;->status:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lio/getlime/core/rest/model/base/entity/a;)V
    .locals 1

    .line 3
    invoke-direct {p0}, Lio/getlime/core/rest/model/base/response/c;-><init>()V

    .line 4
    const-string v0, "ERROR"

    iput-object v0, p0, Lio/getlime/core/rest/model/base/response/c;->status:Ljava/lang/String;

    .line 5
    iput-object p1, p0, Lio/getlime/core/rest/model/base/response/b;->responseObject:Ljava/lang/Object;

    return-void
.end method
