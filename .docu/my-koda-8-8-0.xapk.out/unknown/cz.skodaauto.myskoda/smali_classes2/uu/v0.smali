.class public final synthetic Luu/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqp/b;


# instance fields
.field public final synthetic d:Luu/x0;


# direct methods
.method public synthetic constructor <init>(Luu/x0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/v0;->d:Luu/x0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object p0, p0, Luu/v0;->d:Luu/x0;

    .line 2
    .line 3
    iget-object v0, p0, Luu/x0;->d:Luu/g;

    .line 4
    .line 5
    iget-object v0, v0, Luu/g;->a:Ll2/j1;

    .line 6
    .line 7
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Luu/x0;->d:Luu/g;

    .line 13
    .line 14
    iget-object p0, p0, Luu/x0;->a:Lqp/g;

    .line 15
    .line 16
    invoke-virtual {p0}, Lqp/g;->b()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const-string v1, "getCameraPosition(...)"

    .line 21
    .line 22
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, v0, Luu/g;->c:Ll2/j1;

    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
