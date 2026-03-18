.class public final Lcm/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final d:Lcm/b;


# direct methods
.method public constructor <init>(Lcm/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcm/f;->d:Lcm/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcm/f;->d:Lcm/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcm/b;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
