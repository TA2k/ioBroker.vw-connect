.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/data/FinishStateValues;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u0080\u0008\u0018\u00002\u00020\u0001:\u0001\u0002\u00a8\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/data/FinishStateValues;",
        "kp/x9",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final h:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;


# instance fields
.field public final a:Ls71/h;

.field public final b:Z

.field public final c:Ljava/lang/Boolean;

.field public final d:Ljava/lang/Boolean;

.field public final e:Ljava/lang/Boolean;

.field public final f:Ljava/lang/Boolean;

.field public final g:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 2
    .line 3
    sget-object v1, Ls71/h;->d:Ls71/h;

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    const/4 v7, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    invoke-direct/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;-><init>(Ls71/h;ZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ls71/h;ZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 5
    .line 6
    iput-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 9
    .line 10
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 11
    .line 12
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 13
    .line 14
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 15
    .line 16
    iput-object p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 28
    .line 29
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 30
    .line 31
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 39
    .line 40
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 50
    .line 51
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 61
    .line 62
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 72
    .line 73
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 74
    .line 75
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-nez p0, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    move v3, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    add-int/2addr v0, v3

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_1
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 42
    .line 43
    if-nez v3, :cond_2

    .line 44
    .line 45
    move v3, v2

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    :goto_2
    add-int/2addr v0, v3

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 54
    .line 55
    if-nez v3, :cond_3

    .line 56
    .line 57
    move v3, v2

    .line 58
    goto :goto_3

    .line 59
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_3
    add-int/2addr v0, v3

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 66
    .line 67
    if-nez p0, :cond_4

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_4
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    :goto_4
    add-int/2addr v0, v2

    .line 75
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MEBParkingFinishedStateValues(parkingManeuverStatus="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isTargetPositionReached="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isHavingOpenWindows="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", isEngineTurnedOff="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", isHandbrakeActive="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", isHavingUnlockedDoors="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", isHavingOpenDoorsOrFlaps="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 69
    .line 70
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string p0, ")"

    .line 74
    .line 75
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method
