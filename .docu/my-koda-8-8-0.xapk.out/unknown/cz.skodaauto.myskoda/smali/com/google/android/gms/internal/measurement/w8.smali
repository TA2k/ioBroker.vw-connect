.class public final Lcom/google/android/gms/internal/measurement/w8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/measurement/v8;


# static fields
.field public static final a:Lcom/google/android/gms/internal/measurement/n4;

.field public static final b:Lcom/google/android/gms/internal/measurement/n4;

.field public static final c:Lcom/google/android/gms/internal/measurement/n4;

.field public static final d:Lcom/google/android/gms/internal/measurement/n4;

.field public static final e:Lcom/google/android/gms/internal/measurement/n4;

.field public static final f:Lcom/google/android/gms/internal/measurement/n4;

.field public static final g:Lcom/google/android/gms/internal/measurement/n4;

.field public static final h:Lcom/google/android/gms/internal/measurement/n4;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/m4;->a()Landroid/net/Uri;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lb6/f;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-direct {v1, v0, v2, v2}, Lb6/f;-><init>(Landroid/net/Uri;ZZ)V

    .line 9
    .line 10
    .line 11
    const-string v0, "measurement.rb.attribution.ad_campaign_info"

    .line 12
    .line 13
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 14
    .line 15
    .line 16
    const-string v0, "measurement.rb.attribution.service.bundle_on_backgrounded"

    .line 17
    .line 18
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 19
    .line 20
    .line 21
    const-string v0, "measurement.rb.attribution.client2"

    .line 22
    .line 23
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 28
    .line 29
    const-string v0, "measurement.rb.attribution.followup1.service"

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    invoke-virtual {v1, v0, v3}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->b:Lcom/google/android/gms/internal/measurement/n4;

    .line 37
    .line 38
    const-string v0, "measurement.rb.attribution.client.get_trigger_uris_async"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 41
    .line 42
    .line 43
    const-string v0, "measurement.rb.attribution.service.trigger_uris_high_priority"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->c:Lcom/google/android/gms/internal/measurement/n4;

    .line 50
    .line 51
    const-string v0, "measurement.rb.attribution.index_out_of_bounds_fix"

    .line 52
    .line 53
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 54
    .line 55
    .line 56
    const-string v0, "measurement.rb.attribution.service.enable_max_trigger_uris_queried_at_once"

    .line 57
    .line 58
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->d:Lcom/google/android/gms/internal/measurement/n4;

    .line 63
    .line 64
    const-string v0, "measurement.rb.attribution.retry_disposition"

    .line 65
    .line 66
    invoke-virtual {v1, v0, v3}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->e:Lcom/google/android/gms/internal/measurement/n4;

    .line 71
    .line 72
    const-string v0, "measurement.rb.attribution.service"

    .line 73
    .line 74
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->f:Lcom/google/android/gms/internal/measurement/n4;

    .line 79
    .line 80
    const-string v0, "measurement.rb.attribution.enable_trigger_redaction"

    .line 81
    .line 82
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->g:Lcom/google/android/gms/internal/measurement/n4;

    .line 87
    .line 88
    const-string v0, "measurement.rb.attribution.uuid_generation"

    .line 89
    .line 90
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    sput-object v0, Lcom/google/android/gms/internal/measurement/w8;->h:Lcom/google/android/gms/internal/measurement/n4;

    .line 95
    .line 96
    const-string v0, "measurement.id.rb.attribution.retry_disposition"

    .line 97
    .line 98
    const-wide/16 v3, 0x0

    .line 99
    .line 100
    invoke-virtual {v1, v3, v4, v0}, Lb6/f;->z(JLjava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;

    .line 101
    .line 102
    .line 103
    const-string v0, "measurement.rb.attribution.improved_retry"

    .line 104
    .line 105
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 106
    .line 107
    .line 108
    return-void
.end method
