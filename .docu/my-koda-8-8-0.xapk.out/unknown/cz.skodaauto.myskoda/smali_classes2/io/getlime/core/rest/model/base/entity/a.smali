.class public Lio/getlime/core/rest/model/base/entity/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/getlime/core/rest/model/base/entity/a$a;,
        Lio/getlime/core/rest/model/base/entity/a$b;
    }
.end annotation


# instance fields
.field private code:Ljava/lang/String;

.field private message:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "ERROR_GENERIC"

    .line 5
    .line 6
    iput-object v0, p0, Lio/getlime/core/rest/model/base/entity/a;->code:Ljava/lang/String;

    .line 7
    .line 8
    const-string v0, "UNKNOWN_ERROR"

    .line 9
    .line 10
    iput-object v0, p0, Lio/getlime/core/rest/model/base/entity/a;->message:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method
