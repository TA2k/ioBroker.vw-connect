.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;

.field public final q:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->i:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->k:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p9, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->l:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p10, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->m:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p11, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->n:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p12, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->o:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p13, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->p:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p14, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->q:Ljava/lang/String;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const/16 p2, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    const/4 v0, 0x1

    .line 8
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->d:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->f:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->g:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 29
    .line 30
    .line 31
    const/4 v0, 0x5

    .line 32
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->h:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    const/4 v0, 0x6

    .line 38
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->i:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    const/4 v0, 0x7

    .line 44
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->j:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    const/16 v0, 0x8

    .line 50
    .line 51
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->k:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 54
    .line 55
    .line 56
    const/16 v0, 0x9

    .line 57
    .line 58
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->l:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 61
    .line 62
    .line 63
    const/16 v0, 0xa

    .line 64
    .line 65
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->m:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 68
    .line 69
    .line 70
    const/16 v0, 0xb

    .line 71
    .line 72
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->n:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 75
    .line 76
    .line 77
    const/16 v0, 0xc

    .line 78
    .line 79
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->o:Ljava/lang/String;

    .line 80
    .line 81
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 82
    .line 83
    .line 84
    const/16 v0, 0xd

    .line 85
    .line 86
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->p:Ljava/lang/String;

    .line 87
    .line 88
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 89
    .line 90
    .line 91
    const/16 v0, 0xe

    .line 92
    .line 93
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k;->q:Ljava/lang/String;

    .line 94
    .line 95
    invoke-static {p1, p0, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 96
    .line 97
    .line 98
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 99
    .line 100
    .line 101
    return-void
.end method
