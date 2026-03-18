.class public Lio/getlime/core/rest/model/base/response/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/getlime/core/rest/model/base/response/c$a;
    }
.end annotation


# instance fields
.field protected status:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "OK"

    .line 5
    .line 6
    iput-object v0, p0, Lio/getlime/core/rest/model/base/response/c;->status:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method
