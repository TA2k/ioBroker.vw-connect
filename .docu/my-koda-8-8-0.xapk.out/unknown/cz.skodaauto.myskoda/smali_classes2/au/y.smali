.class public abstract Lau/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcom/google/protobuf/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget-object v0, Lcom/google/protobuf/u1;->g:Lcom/google/protobuf/q1;

    .line 2
    .line 3
    sget-object v1, Lcom/google/protobuf/u1;->f:Lcom/google/protobuf/u1;

    .line 4
    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    new-instance v3, Lcom/google/protobuf/h0;

    .line 12
    .line 13
    invoke-direct {v3, v0, v1, v2}, Lcom/google/protobuf/h0;-><init>(Lcom/google/protobuf/u1;Lcom/google/protobuf/u1;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    sput-object v3, Lau/y;->a:Lcom/google/protobuf/h0;

    .line 17
    .line 18
    return-void
.end method
